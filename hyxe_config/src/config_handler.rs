use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Error, Formatter, Write};
use std::path::{Path, PathBuf};
use log::info;
use crate::error::ConfigError;

pub const CONFIG_EXT: &str = ".hfg";
pub const FILE_HEADER: &str = "#!START_FILE";
pub const FILE_END: &str = "#!END_FILE";
pub const SECTION_START: &str = "\t##SECTION";
pub const SECTION_END: &str = "\t##END_SECTION";
pub const ATTR_TAG: &str = "\t\t##ATTR";
pub const SUBSECTION_START: &str = "\t\t###SUBSECTION";
pub const SUBSECTION_END: &str = "\t\t###END_SUBSECTION";
pub const DATA_POINTER: &str = " -> ";
pub const DATA_SPLITTER: &str = " [|] ";
pub const EMPTY_MAP_ENTRY: &str = "<empty>";

/// The basic file type that allows interfacing with the information contained within the path
#[allow(dead_code)]
pub struct ConfigFile {
    /// location of the file, including the filename
    path: PathBuf,
    config: ParsedConfig,
}

impl ConfigFile {
    /// Creates a file at an absolute location on the local hard drive. Will overwrite if there already exists data
    pub async fn create<P: AsRef<Path>>(location: P, data: Option<String>) -> Result<Self, ConfigError> {
        let path_no_filename = location.as_ref().parent().unwrap().clone();
        info!("Storing ConfigFile to directory: {}", &path_no_filename.display());
        tokio::fs::create_dir_all(&path_no_filename).await.map_err(|err| ConfigError::IoError(err.to_string()))?;
        let path = format!("{}{}", location.as_ref().to_str().unwrap(), CONFIG_EXT);
        tokio::fs::File::create(&path)
            .await
            .map_err(|err| ConfigError::Generic(err.to_string()))
            .and_then(|_| {
                ParsedConfig::parse(data.unwrap_or(Self::get_skeleton()))
            })
            .and_then(|config| {
                Ok(Self { path: PathBuf::from(path), config })
            })
    }

    /// Opens a HFG file
    pub async fn load<P: AsRef<Path>>(location: P) -> Result<Self, ConfigError> {
        let path = location.as_ref();

        let path = {
            if path.to_str().unwrap().ends_with(CONFIG_EXT) {
                format!("{}", location.as_ref().to_str().unwrap())
            } else {
                format!("{}{}", location.as_ref().to_str().unwrap(), CONFIG_EXT)
            }
        };

        tokio::fs::read_to_string(&path)
            .await
            .map_err(|err| ConfigError::IoError(err.to_string()))
            .and_then(|data| {
                ParsedConfig::parse(data)
            })
            .and_then(|config| {
                Ok(Self { path: PathBuf::from(path), config })
            })
    }

    /// Saves the data to the local filesystem, recompiling if necessary
    pub async fn save(&mut self) -> Result<(), ConfigError> {
        if self.needs_recompile() {
            self.config.recompile();
        }

        println!("RECOMP: {}", self.config.compiled.as_ref().unwrap());

        match tokio::fs::File::create(&self.path).await {
            Ok(_) => {
                tokio::fs::write(self.path.as_path(), self.config.compiled.as_ref().unwrap()).await
                    .map_err(|err| ConfigError::IoError(err.to_string()))
            },

            Err(err) => {
                Err(ConfigError::IoError(err.to_string()))
            }
        }
    }

    /// Returns an immutable reference to an entire section in memory
    pub fn get_section<T: ToString>(&self, section: T) -> Result<&Section, ConfigError> {
        match self.config.sections.get(&section.to_string()) {
            Some(val) => Ok(val),
            None => Err(ConfigError::Generic(format!("Section {} not found", section.to_string())))
        }
    }

    /// Returns whether or not a section exists
    pub fn section_exists<T: ToString>(&self, section: T) -> bool {
        self.config.sections.contains_key(&section.to_string())
    }

    /// Adds a section. Returns an error if the section already exists
    #[allow(unused_results)]
    pub fn add_section<T: ToString>(&mut self, section: T) -> Result<(), ConfigError> {
        let section = section.to_string();
        if !self.config.sections.contains_key(&section) {
            self.config.needs_recompile = true;

            self.config.sections.insert(section.clone(), Section {
                name: section,
                sub_sections: Default::default(),
                attributes: Default::default(),
                notes: vec![],
            });

            Ok(())
        } else {
            Err(ConfigError::Generic(format!("Section {} already exists", section)))
        }
    }

    /// Removes a section, including all its inner contents. Returns the old contents
    pub fn remove_section<T: ToString>(&mut self, section: T) -> Result<Section, ConfigError> {
        let section = section.to_string();
        if let Some(sec) = self.config.sections.remove(&section) {
            Ok(sec)
        } else {
            Err(ConfigError::Generic(format!("Section {} does not exist", section)))
        }
    }

    /// Removes a section, including all its inner contents. Unlike `remove_section`, this does NOT return the old contents
    pub fn delete_section<T: AsRef<str>>(&mut self, section: T) -> Result<(), ConfigError> {
        let section = section.as_ref();
        if let Some(_) = self.config.sections.remove(section) {
            Ok(())
        } else {
            Err(ConfigError::Generic(format!("Section {} does not exist", section)))
        }
    }

    /// Returns an immutable reference to an entire subsection in memory
    pub fn get_subsection_mut<T: AsRef<str>, V: AsRef<str>>(&mut self, section: T, subsection: V) -> Result<&mut Subsection, ConfigError> {
        let section = section.as_ref();
        match self.config.sections.get_mut(section) {
            Some(val) => {
                let subsection = subsection.as_ref();
                match val.sub_sections.get_mut(subsection) {
                    Some(ss) => Ok(ss),
                    None => Err(ConfigError::Generic(format!("Subsection {} not found", subsection)))
                }
            }
            None => Err(ConfigError::Generic(format!("Section {} not found", section)))
        }
    }

    /// Returns an immutable reference to an entire subsection in memory
    pub fn get_subsection<T: AsRef<str>, V: AsRef<str>>(&self, section: T, subsection: V) -> Result<&Subsection, ConfigError> {
        let section = section.as_ref();
        match self.config.sections.get(section) {
            Some(val) => {
                let subsection = subsection.as_ref();
                match val.sub_sections.get(subsection) {
                    Some(ss) => Ok(ss),
                    None => Err(ConfigError::Generic(format!("Subsection {} not found", subsection)))
                }
            }
            None => Err(ConfigError::Generic(format!("Section {} not found", section)))
        }
    }

    /// Returns whether or not a subsection exists
    pub fn subsection_exists<T: AsRef<str>, V: AsRef<str>>(&self, section: T, subsection: V) -> bool {
        let section = section.as_ref();

        if self.section_exists(section) {
            return self.config.sections.get(section).unwrap().sub_sections.contains_key(subsection.as_ref());
        }

        false
    }

    /// Adds a section. Returns an error if the section already exists
    #[allow(unused_results)]
    pub fn add_subsection<T: ToString, V: ToString>(&mut self, section: T, subsection: V, field_type: SubsectionType) -> Result<(), ConfigError> {
        let section = section.to_string();
        if let Some(sect) = self.config.sections.get_mut(&section) {
            let subsection = subsection.to_string();
            if !sect.sub_sections.contains_key(&subsection) {
                self.config.needs_recompile = true;

                sect.sub_sections.insert(subsection.clone(), Subsection {
                    name: subsection,
                    parent: section,
                    fields: HashMap::new(),
                    field_type,
                });

                Ok(())
            } else {
                Err(ConfigError::Generic(format!("Subsection {} already exists within section {}", subsection, section)))
            }
        } else {
            Err(ConfigError::Generic(format!("Section {} already exists", section)))
        }
    }

    /// Removes a section, including all its inner contents. Returns the old contents
    pub fn remove_subsection<T: ToString, V: ToString>(&mut self, section: T, subsection: V) -> Result<Subsection, ConfigError> {
        let section = section.to_string();
        if let Some(sec) = self.config.sections.get_mut(&section) {
            let subsection = subsection.to_string();
            if let Some(ssec) = sec.sub_sections.remove(&subsection) {
                Ok(ssec)
            } else {
                Err(ConfigError::Generic(format!("Subsection {} does not exists within section {}", subsection, section)))
            }
        } else {
            Err(ConfigError::Generic(format!("Section {} does not exist", section)))
        }
    }

    /// Removes a section, including all its inner contents. Returns the old contents
    pub fn delete_subsection<T: ToString, V: ToString>(&mut self, section: T, subsection: V) -> Result<(), ConfigError> {
        let section = section.to_string();
        if let Some(sec) = self.config.sections.get_mut(&section) {
            let subsection = subsection.to_string();
            if let Some(_) = sec.sub_sections.remove(&subsection) {
                Ok(())
            } else {
                Err(ConfigError::Generic(format!("Subsection {} does not exist within section {}", subsection, section)))
            }
        } else {
            Err(ConfigError::Generic(format!("Section {} does not exist", section)))
        }
    }

    /// Returns whether or not an entry exists
    pub fn get_field<T: AsRef<str>, V: AsRef<str>, K: AsRef<str>>(&self, section: T, subsection: V, entry: K) -> Result<&FieldEntry, ConfigError> {
        let section = section.as_ref();
        let subsection = subsection.as_ref();

        let ss = self.get_subsection(section, subsection)?;
        let field = entry.as_ref();
        log::info!("Checking to see if field {} exists", field);
        match ss.fields.get(field) {
            Some(field) => {
                Ok(field)
            }

            _ => {
                Err(ConfigError::IoError(format!("Field {} within subsection {} of section {} does not exist", entry.as_ref(), subsection, section)))
            }
        }
    }

    /// Returns whether or not an entry exists
    pub fn get_field_mut<T: AsRef<str>, V: AsRef<str>, K: AsRef<str>>(&mut self, section: T, subsection: V, entry: K) -> Result<&mut FieldEntry, ConfigError> {
        let section = section.as_ref();
        let subsection = subsection.as_ref();

        let ss = self.get_subsection_mut(section, subsection)?;
        match ss.fields.get_mut(entry.as_ref()) {
            Some(field) => {
                Ok(field)
            }

            _ => {
                Err(ConfigError::IoError(format!("Field {} within subsection {} of section {} does not exist", entry.as_ref(), subsection, section)))
            }
        }
    }

    /// Returns whether or not an entry exists
    pub fn field_exists<T: AsRef<str>, V: AsRef<str>, K: AsRef<str>>(&self, section: T, subsection: V, entry: K) -> bool {
        self.get_field(section, subsection, entry).is_ok()
    }

    /// Adds a single row into a subsection. This will return an error if the subsection is not a list or undefined type
    #[allow(unused_results)]
    pub fn add_list_field<T: AsRef<str>, R: AsRef<str>, J: ToString>(&mut self, section: T, subsection: R, field: J) -> Result<(), ConfigError> {
        let ss = self.get_subsection_mut(section.as_ref(), subsection.as_ref())?;

        if ss.field_type != SubsectionType::List && ss.field_type != SubsectionType::Null {
            println!("Bad type {}", ss.field_type);
            return Err(ConfigError::IoError(format!("The subsection {} within section {} is not a list or undefined type", subsection.as_ref(), section.as_ref())));
        }

        let entry = FieldEntry {
            field_type: ss.field_type,
            field_values: Vec::with_capacity(0),
        };

        ss.fields.insert(field.to_string(), entry);
        self.config.needs_recompile = true;

        Ok(())
    }

    /// Adds a single mapping into a subsection. This will return an error if the subsection is not a map type
    #[allow(unused_results)]
    pub fn add_map_field<T: AsRef<str>, R: AsRef<str>, J: ToString, V: ToString>(&mut self, section: T, subsection: R, field: J, value: V) -> Result<(), ConfigError> {
        let ss = self.get_subsection_mut(section.as_ref(), subsection.as_ref())?;

        if ss.field_type != SubsectionType::Map {
            return Err(ConfigError::IoError(format!("The subsection {} within section {} is not a Map type", subsection.as_ref(), section.as_ref())));
        }

        let field = field.to_string();

        let entry = SubsectionType::Map.parse_field_value(field.as_str(), value);
        ss.fields.insert(field, entry);
        self.config.needs_recompile = true;

        Ok(())
    }

    /// Adds an array of values to a single subsection's field. This will return an error if the subsection is not a multimap type
    #[allow(unused_results)]
    pub fn add_multimap_field<T: AsRef<str>, R: AsRef<str>, J: ToString, V: ToString, K: AsRef<[V]>>(&mut self, section: T, subsection: R, field: J, values: K) -> Result<(), ConfigError> {
        let ss = self.get_subsection_mut(section.as_ref(), subsection.as_ref())?;
        if ss.field_type != SubsectionType::Multimap {
            return Err(ConfigError::IoError(format!("The subsection {} within section {} is not a Multimap type", subsection.as_ref(), section.as_ref())));
        }

        let field = field.to_string();

        let entry = SubsectionType::Multimap.field_values_to_multimap(field.as_str(), values);
        ss.fields.insert(field, entry);
        self.config.needs_recompile = true;

        Ok(())
    }

    /// Returns the values associated with an entry. The subsection must be either a map or a multimap type
    pub fn get_field_values<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>>(&self, section: T, subsection: R, field: V) -> Result<&[String], ConfigError> {
        let field = self.get_field(section, subsection, field)?;
        assert!(field.field_type != SubsectionType::Null && field.field_type != SubsectionType::List);
        Ok(field.field_values.as_ref())
    }

    /// Returns Ok(true) if the value exists in the field, or Ok(false) if it does not. This return an error otherwise
    pub fn field_value_exists<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>, K: AsRef<str>>(&self, section: T, subsection: R, field: V, value: K) -> Result<bool, ConfigError> {
        let field_values = self.get_field_values(section, subsection, field)?;
        let check_value = value.as_ref();
        for field_value in field_values {
            if field_value.as_str() == check_value {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Unlike Self::field_value_exists, this checks ALL entries under a subsection to see if a particular field value exists
    pub fn field_value_exists_in_subsection<T: AsRef<str>, R: AsRef<str>, K: AsRef<str>>(&self, section: T, subsection: R, value: K) -> Result<bool, ConfigError> {
        let subsection = self.get_subsection(section, subsection)?;
        let check_value = value.as_ref();

        for field in subsection.fields.values() {
            for field_value in field.field_values.iter() {
                if field_value == check_value {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Removes a singular field from a subsection. If the entry does not exist, or the section/subsection do not exists, returns an error
    #[allow(unused_results)]
    pub fn remove_field<T: AsRef<str>, V: AsRef<str>, K: AsRef<str>>(&mut self, section: T, subsection: V, field: K) -> Result<(), ConfigError> {
        let ss = self.get_subsection_mut(section.as_ref(), subsection.as_ref())?;

        let field = field.as_ref();
        match ss.fields.remove(field) {
            Some(_) => {
                self.config.needs_recompile = true;
                return Ok(());
            }

            _ => {
                Err(ConfigError::Generic(format!("Field {} does not exists within subsection {} of section {}", field, section.as_ref(), subsection.as_ref())))
            }
        }
    }

    /// Removes multiple list fields from a subsection. If you wish to remove the entire subsection without clearing the structure, enter ["*"].
    #[allow(unused_results)]
    pub fn remove_list_fields<T: AsRef<str>, V: AsRef<str>, K: AsRef<str>, J: AsRef<[K]>>(&mut self, section: T, subsection: V, fields: J) -> Result<usize, ConfigError> {
        let ss = self.get_subsection_mut(section.as_ref(), subsection.as_ref())?;

        let fields = fields.as_ref();

        if fields.len() == 1 {
            if fields[0].as_ref() == "*" {
                let amt = ss.fields.len();
                ss.fields.clear();
                self.config.needs_recompile = true;
                return Ok(amt);
            }
        }

        let mut found_indexes = vec![false; fields.len()];
        let mut count = 0;

        ss.fields.retain(|line, _| unsafe {
            for (idx, entry) in fields.iter().enumerate() {
                let found_index = (&mut found_indexes).get_unchecked_mut(idx);
                if !*found_index {
                    if line == entry.as_ref() {
                        *found_index = true;
                        count += 1;
                        return false;
                    }
                }
            }

            true
        });

        if count > 0 {
            self.config.needs_recompile = true;
        }

        Ok(count)
    }

    /// Removes a set of entries from a subsection. If you wish to remove the entire subsection without clearing the structure, enter ["*"].
    /// This returns the number of entries removed
    pub fn remove_fields<T: AsRef<str>, V: AsRef<str>, K: AsRef<str>, I: AsRef<[K]>>(&mut self, section: T, subsection: V, entries: I) -> Result<usize, ConfigError> {
        let ss = self.get_subsection_mut(section, subsection)?;

        let entries = entries.as_ref();
        if entries.len() == 1 {
            if entries[0].as_ref() == "*" {
                let amt = ss.fields.len();
                ss.fields.clear();
                self.config.needs_recompile = true;
                return Ok(amt);
            }
        }

        let mut found_indexes = vec![false; entries.len()];
        let mut count = 0;

        ss.fields.retain(|line, _| unsafe {
            for (idx, entry) in entries.iter().enumerate() {
                let found_index = (&mut found_indexes).get_unchecked_mut(idx);
                if !*found_index {
                    if line == entry.as_ref() {
                        *found_index = true;
                        count += 1;
                        return false;
                    }
                }
            }

            true
        });

        Ok(count)
    }

    /// Removes a specific entry from the configuration. If `field_value` is_none, then this will entirely remove the field
    pub fn remove_field_value<T: AsRef<str>, R: AsRef<str>, V: AsRef<str>, K: AsRef<str>>(&mut self, section: T, subsection: R, field: V, field_value: K) -> Result<(), ConfigError> {
        let ss = self.get_field_mut(section.as_ref(), subsection.as_ref(), field.as_ref())?;

        let field_value = field_value.as_ref();

        //let len = ss.field_values.len();
        let mut idx_to_remove = None;
        for (idx, data) in ss.field_values.iter().enumerate() {
            if data == field_value {
                idx_to_remove = Some(idx);
                break;
            }
        }
        //ss.field_values.retain(|sse| sse != field_value);

        if let Some(idx) = idx_to_remove {
            let _ = ss.field_values.remove(idx);
            Ok(())
        } else {
            let msg = format!("Entry {} within Field {} not found in subsection {} of section {}", field_value, field.as_ref(), subsection.as_ref(), section.as_ref());
            println!("ERR: {}", &msg);
            Err(ConfigError::IoError(msg))
        }
    }

    /// Removes a set of entries from a subsection. If you wish to remove the entire subsection without clearing the structure, enter ["*"].
    /// This returns the number of entries removed
    pub fn remove_field_values<T: AsRef<str>, V: AsRef<str>, J: AsRef<str>, K: AsRef<str>, I: AsRef<[K]>>(&mut self, section: T, subsection: V, field: J, field_values: I) -> Result<usize, ConfigError> {
        let ss = self.get_field_mut(section, subsection, field)?;

        if ss.field_type != SubsectionType::Map && ss.field_type != SubsectionType::Multimap {
            return Err(ConfigError::IoError("This subroutine may only be used upon Map and Multimap types".to_string()));
        }

        let field_values = field_values.as_ref();

        let mut found_indexes = vec![false; field_values.len()];
        let mut count = 0;

        ss.field_values.retain(|line| unsafe {
            for (idx, entry) in field_values.iter().enumerate() {
                let found_index = (&mut found_indexes).get_unchecked_mut(idx);
                if !*found_index {
                    if line == entry.as_ref() {
                        *found_index = true;
                        count += 1;
                        return false;
                    }
                }
            }

            true
        });

        Ok(count)
    }

    /// When using the get_section, get_subsection, or any other mutable getter function, make sure to call this
    pub fn custom_edit_made(&mut self) {
        self.config.needs_recompile = true;
    }

    /// Manually Compiles the underlying data
    pub fn recompile(&mut self) -> Result<(), ConfigError> {
        Ok(self.config.recompile())
    }

    /// Returns the text from the last compile
    pub fn get_compiled_text(&self) -> Option<&String> {
        self.config.compiled.as_ref()
    }

    /// Returns whether or not the underlying data in memory needs to be re-compiled
    pub fn needs_recompile(&self) -> bool {
        self.config.needs_recompile
    }

    /// Compiles the underlying data manually

    fn get_skeleton() -> String {
        FILE_HEADER.to_owned() + "\n" +
            SECTION_START + " notes\n" +
            "\t\tFeel free to add annotations in this unique SECTION block\nComments under the 'notes' section will always appear at the very top of the document\nHowever, you may add comments in any section outside of the subsections\n" +
            SECTION_END + " notes\n" +
            SECTION_START + " default\n" +
            ATTR_TAG + " encoding utf8\n" +
            SECTION_END + " default\n" +
            FILE_END
    }
}

/// The object describing the information within a config file. This allows for fast I/O,
/// as adding entries is in O(1) time instead of O(n^2) time. The sync process converts
/// the internally stored ParsedConfig into an array of lines which are then written to the disk.
pub struct ParsedConfig {
    /// Contains all the sections that were parsed
    pub(super) sections: HashMap<String, Section>,
    pub(super) needs_recompile: bool,
    pub(super) compiled: Option<String>,
}

impl ParsedConfig {
    /// Parses an input string, usually read directly from a formatted file
    pub fn parse(input: String) -> Result<Self, ConfigError> {
        let mut in_section = false;
        let mut current_section_name = String::new();
        let mut section_map_ret = HashMap::<String, Section>::new();
        let section_map = &mut section_map_ret;

        let mut in_subsection = false;
        let mut current_subsection_name = String::new();
        // stored at the zero-index
        let mut current_subsection = Vec::new();
        let current_subsection = &mut current_subsection;

        // At the end of each section, the attributed get drained into a new hashmap for the corresponding section
        let mut attributes_current_section = HashMap::new();
        let attributes_current_section = &mut attributes_current_section;

        let lines = input.lines();
        let last_line = lines.count() - 1;

        let vec: Vec<(usize, &str)> = input.lines().enumerate().collect();

        for (line_number, line) in vec {
            //println!("[{}] PARSING {}", line_number, line);

            match line_number {
                0 => {
                    if line != FILE_HEADER {
                        return Err(ConfigError::IoError(format!("Parse error on line 0. Input \"{}\" is invalid", line)));
                    }
                }

                final_line if final_line == last_line => {
                    if line != FILE_END {
                        return Err(ConfigError::IoError(format!("Parse error on line {}. Input \"{}\" is invalid", final_line, line)));
                    }
                }

                _ => {
                    if line.starts_with(&(SECTION_START.to_owned() + " ")) {
                        debug_assert_eq!(in_section, false);
                        debug_assert_eq!(current_subsection.is_empty(), true);

                        if in_subsection {
                            return Err(ConfigError::IoError(format!("Parse error. SUBSECTION tag unclosed on line {}", line_number)));
                        }

                        current_section_name = line.replace(&(SECTION_START.to_owned() + " "), "");

                        if let Some(_) = section_map.insert(current_section_name.clone(), Section {
                            name: current_section_name.clone(),
                            sub_sections: Default::default(),
                            attributes: Default::default(),
                            notes: Vec::new(),
                        }) {
                            return Err(ConfigError::IoError(format!("Section {} already exists!", &current_section_name)));
                        }

                        in_section = true;
                    } else if line.starts_with(&(SECTION_END.to_owned() + " ")) {
                        debug_assert_eq!(in_section, true);

                        if !current_subsection.is_empty() {
                            return Err(ConfigError::IoError(format!("Parse error when reaching SECTION_END. SUBSECTION tag unclosed on line {}", line_number)));
                        }

                        if let Some(section_map) = section_map.get_mut(&current_section_name) {
                            attributes_current_section.shrink_to_fit();
                            section_map.attributes.extend(attributes_current_section.drain());
                        }

                        in_section = false;
                    } else if line.starts_with(&(SUBSECTION_START.to_owned() + " ")) {
                        if in_subsection {
                            return Err(ConfigError::IoError(format!("Parse error when reaching SUBSECTION_START. SUBSECTION tag unclosed on line {}", line_number)));
                        }
                        debug_assert_eq!(in_section, true);
                        debug_assert_eq!(current_subsection.is_empty(), true);
                        in_subsection = true;
                        let name = line.replace(&(SUBSECTION_START.to_owned() + " "), "");

                        let field_type = SubsectionType::try_from(name.as_str())?;
                        let name = name.replace("as list", "").replace("as map", "").replace("as multimap", "").replace(" ", "");

                        current_subsection.push(Subsection { name: name.clone(), parent: current_section_name.to_owned(), fields: HashMap::new(), field_type });
                        current_subsection_name = name;
                    } else if line.starts_with(SUBSECTION_END) {
                        debug_assert_eq!(in_subsection, true);
                        debug_assert_eq!(!current_subsection.is_empty(), true);
                        in_subsection = false;
                        if let Some(cur_section) = section_map.get_mut(&current_section_name) {
                            if !cur_section.sub_sections.contains_key(&current_subsection_name) {
                                let _ = cur_section.sub_sections.insert(current_subsection_name.clone(), current_subsection.pop().unwrap());
                                current_subsection.clear();
                            } else {
                                return Err(ConfigError::IoError(format!("Subsection {} already exists within section {}", &current_subsection_name, &current_section_name)));
                            }
                        } else {
                            return Err(ConfigError::IoError(format!("Unable to add subsection {} to non-existent section {}", &current_subsection_name, &current_section_name)));
                        }
                    } else if line.starts_with(&(ATTR_TAG.to_owned() + " ")) {
                        let parts: Vec<&str> = line.split_whitespace().into_iter().collect();
                        if parts.len() > 2 {
                            if let Some(attr) = attributes_current_section.insert(parts[1].to_string(), parts[2].to_string()) {
                                return Err(ConfigError::IoError(format!("Parse error. #ATTR tag {} duplicated on line {}", attr, line_number)));
                            }
                        } else {
                            return Err(ConfigError::IoError(format!("Parse error. Invalid #ATTR tag on line {}", line_number)));
                        }
                    } else {
                        // If we are in here, it means we are either in an untagged region (throw error), or are in_subsection. We may need to also parse notes

                        if in_section && !in_subsection {
                            if let Some(section) = section_map.get_mut(&current_section_name) {
                                section.notes.push(line.replace("\t", ""));
                            } else {
                                unreachable!()
                            }

                            continue;
                        }

                        if !in_subsection {
                            return Err(ConfigError::IoError(format!("Parse error. Untagged and/or invalid line item {} on line {}", line, line_number)));
                        }

                        if !current_subsection.is_empty() {
                            unsafe {
                                let raw_line = line.replace("\t", "");
                                let (name, entry) = match current_subsection.get_unchecked_mut(0).field_type {
                                    SubsectionType::List => {
                                        SubsectionType::List.parse(raw_line)
                                    }

                                    SubsectionType::Map => {
                                        SubsectionType::Map.parse(raw_line)
                                    }

                                    SubsectionType::Multimap => {
                                        SubsectionType::Multimap.parse(raw_line)
                                    }

                                    SubsectionType::Null => {
                                        SubsectionType::Null.parse(raw_line)
                                    }
                                };

                                let _ = current_subsection.get_unchecked_mut(0).fields.insert(name, entry);
                            }
                        } else {
                            return Err(ConfigError::IoError(format!("Subsection is none when it as expected to exist. Please check your file for inconsistency")));
                        }
                    }
                }
            }
        }

        let cfg = ParsedConfig { sections: section_map_ret, needs_recompile: true, compiled: None };
        //cfg.recompile();

        Ok(cfg)
    }

    /// Compiles the object into a text-friendly representation
    #[allow(unused_results)]
    fn compile(&self) -> String {
        let mut out = String::new();
        writeln!(out, "{}", FILE_HEADER).unwrap();

        if self.sections.contains_key("notes") {
            if let Some(special_note_section) = self.sections.get("notes") {
                writeln!(out, "{} {}", SECTION_START, "notes").unwrap();
                writeln!(out).unwrap();
                for note in &special_note_section.notes {
                    writeln!(out, "\t\t{}", note).unwrap();
                }
                writeln!(out).unwrap();
                writeln!(out, "{} {}", SECTION_END, "notes").unwrap();
            }
        }

        for (section_name, section) in &self.sections {
            if section_name != "notes" {
                writeln!(out, "{} {}", SECTION_START, &section_name).unwrap();
                for (attr_name, attr_value) in &section.attributes {
                    writeln!(out, "{} {} {}", ATTR_TAG, attr_name, attr_value).unwrap();
                }

                if !section.notes.is_empty() {
                    writeln!(out).unwrap();
                    for note in &section.notes {
                        writeln!(out, "\t\t{}", note).unwrap();
                    }
                    writeln!(out).unwrap();
                }

                for (subsection_name, subsection) in &section.sub_sections {
                    match subsection.field_type {
                        SubsectionType::List => {
                            writeln!(out, "{} {} as list", SUBSECTION_START, &subsection_name).unwrap();
                            for line in &subsection.fields {
                                writeln!(out, "\t\t\t{}", line.0).unwrap();
                            }
                        }

                        SubsectionType::Map => {
                            println!("Compiling map {}", subsection_name);
                            writeln!(out, "{} {} as map", SUBSECTION_START, &subsection_name).unwrap();
                            for line in &subsection.fields {
                                if let Some(val) = line.1.field_values.get(0) {
                                    writeln!(out, "\t\t\t{}{}{}", line.0, DATA_POINTER, val).unwrap();
                                } else {
                                    writeln!(out, "\t\t\t{}{}{}", line.0, DATA_POINTER, EMPTY_MAP_ENTRY).unwrap();
                                }
                            }
                        }

                        SubsectionType::Multimap => {
                            writeln!(out, "{} {} as multimap", SUBSECTION_START, &subsection_name).unwrap();
                            for line in &subsection.fields {
                                if line.1.field_values.is_empty() {
                                    writeln!(out, "\t\t\t{}{}{}", line.0, DATA_POINTER, EMPTY_MAP_ENTRY).unwrap();
                                } else {
                                    let mut ret = String::new();
                                    let len = line.1.field_values.len();

                                    for (idx, field_value) in line.1.field_values.iter().enumerate() {
                                        ret.push_str(field_value.as_str());
                                        if idx != len - 1 {
                                            ret.push_str(DATA_SPLITTER)
                                        }
                                    }

                                    writeln!(out, "\t\t\t{}{}{}", line.0, DATA_POINTER, &ret).unwrap();
                                }
                            }
                        }

                        SubsectionType::Null => {
                            writeln!(out, "{} {}", SUBSECTION_START, &subsection_name).unwrap();
                            for line in &subsection.fields {
                                writeln!(out, "\t\t\t{}", line.0).unwrap();
                            }
                        }
                    }
                    writeln!(out, "{} {}", SUBSECTION_END, &subsection_name).unwrap();
                }

                writeln!(out, "{} {}", SECTION_END, &section_name).unwrap();
            }
        }

        writeln!(out, "{}", FILE_END).unwrap();
        out.replace("\n\n", "\n")
    }

    /// Updates the internal data ontop of a normal compilation
    pub fn recompile(&mut self) {
        //self.sort();
        self.compiled = Some(self.compile());
        self.needs_recompile = false;
    }

    /*
    /// Sorts the lists alphabetically
    fn sort(&mut self) {
        self.sections.sort_by(|a, _, c, _| a.to_lowercase().cmp(&c.to_lowercase()));
        for section in &mut self.sections {
            section.1.sub_sections.sort_by(|a, _, c, _| a.to_lowercase().cmp(&c.to_lowercase()));
        }
    }
     */
}

impl Display for ParsedConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let empty = "Not compiled yet!".to_string();
        let data = if let Some(data) = self.compiled.as_ref() {
            data
        } else {
            &empty
        };

        write!(f, "{}", data)
    }
}

/// Obtained when parsing a ConfigFile for a particular section
pub struct Section {
    /// The name of the section
    pub name: String,
    /// Any possible subsections within the section block
    pub sub_sections: HashMap<String, Subsection>,
    /// Any possible ##ATTR lines
    pub attributes: HashMap<String, String>,
    /// Untagged lines in between sections and subsections. Notes cannot go inside subsections because those are pure data
    pub notes: Vec<String>,
}

/// A subsection to a section. Denoted by ##SUBSECTION <name>
pub struct Subsection {
    /// The name of the subsection
    pub name: String,
    /// The parent section's name
    pub parent: String,
    /// The lines of information contained within the subsection
    pub fields: HashMap<String, FieldEntry>,
    /// The subsection type,
    pub field_type: SubsectionType,
}

impl Subsection {
    /// Adds a value to the list
    #[allow(unused_results)]
    pub fn add_list_item<T: ToString>(&mut self, name: T) -> Result<(), ConfigError> {
        if self.field_type != SubsectionType::List {
            Err(ConfigError::IoError("Not a list type".to_string()))
        } else {
            let field = FieldEntry { field_type: SubsectionType::List, field_values: Vec::with_capacity(0) };
            self.fields.insert(name.to_string(), field);
            Ok(())
        }
    }

    /// Inserts a value into the map
    #[allow(unused_results)]
    pub fn add_map_item<T: ToString, R: ToString>(&mut self, name: T, value: R) -> Result<(), ConfigError> {
        if self.field_type != SubsectionType::Map {
            Err(ConfigError::IoError("Not a map or multimap type".to_string()))
        } else {
            let mut field = FieldEntry { field_type: SubsectionType::Map, field_values: Vec::with_capacity(1) };
            field.field_values.push(value.to_string());
            self.fields.insert(name.to_string(), field);
            Ok(())
        }
    }

    /// Inserts an entry of set of entries into the multimap
    #[allow(unused_results)]
    pub fn add_multimap_item<T: ToString, R: ToString, V: AsRef<[R]>>(&mut self, name: T, values: V) -> Result<(), ConfigError> {
        if self.field_type != SubsectionType::Map {
            Err(ConfigError::IoError("Not a map or multimap type".to_string()))
        } else {
            let values = values.as_ref();
            let mut field = FieldEntry { field_type: SubsectionType::Multimap, field_values: Vec::with_capacity(values.len()) };
            for value in values {
                field.field_values.push(value.to_string());
            }

            self.fields.insert(name.to_string(), field);
            Ok(())
        }
    }
}

/// A single value within a subsection type
pub struct FieldEntry {
    field_type: SubsectionType,
    field_values: Vec<String>,
}

impl FieldEntry {
    /// returns the field type
    pub fn get_field_type(&self) -> SubsectionType {
        self.field_type
    }

    /// Returns a list of the values. This will panic if the type is not a map or multimap type
    pub fn get_mapping_values(&self) -> &[String] {
        assert!(self.field_type == SubsectionType::Map || self.field_type == SubsectionType::Multimap);
        self.field_values.as_ref()
    }

    /// Returns true if the value exists
    pub fn value_exists<T: AsRef<str>>(&self, field_value: T) -> bool {
        let field_value = field_value.as_ref();

        for value in &self.field_values {
            if value == field_value {
                return true;
            }
        }

        false
    }

    /// Returns the number of entries
    pub fn len(&self) -> usize {
        self.field_values.len()
    }
}

/// Denotes whether a subsection is a list type, map type, or null type
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SubsectionType {
    /// Values are listed without any inherent value mapping. This is a single column of values with an arbitrary number of rows
    List,
    /// Each entry has an entry key followed by a corresponding key value. There are two columns with an arbitrary number of rows
    Map,
    /// Each entry can store multiple values, which are comma-separated. There are an arbitrary number of columns with an arbitrary number of rows
    Multimap,
    /// Undefined (not specified; will treat as a list type
    Null,
}

impl SubsectionType {
    fn parse<T: AsRef<str>>(self, line: T) -> (String, FieldEntry) {
        let line = line.as_ref();
        match self {
            SubsectionType::List => {
                (line.to_string(), FieldEntry {
                    field_type: SubsectionType::List,
                    field_values: Vec::with_capacity(0),
                })
            }

            SubsectionType::Map => {
                let inputs = line.split(DATA_POINTER).collect::<Vec<&str>>();
                assert_eq!(inputs.len(), 2);
                (inputs[0].to_string(), self.parse_field_value(inputs[0], inputs[1]))
            }

            SubsectionType::Multimap => {
                let first_idx = line.find(" ").unwrap();
                let (field_name, values) = line.split_at(first_idx);
                let values = values.replace(DATA_POINTER, "");
                (field_name.to_string(), self.parse_field_value(field_name, values))
            }

            SubsectionType::Null => {
                (line.to_string(), FieldEntry {
                    field_type: SubsectionType::Null,
                    field_values: Vec::with_capacity(0),
                })
            }
        }
    }

    fn parse_field_value<T: ToString, R: ToString>(self, _: T, value: R) -> FieldEntry {
        match self {
            SubsectionType::Map => {
                let value = value.to_string();

                let field_values = if value == EMPTY_MAP_ENTRY {
                    Vec::with_capacity(0)
                } else {
                    let mut field_values = Vec::with_capacity(1);
                    field_values.push(value);
                    field_values
                };

                FieldEntry {
                    field_type: SubsectionType::Map,
                    field_values,
                }
            }

            SubsectionType::Multimap => {
                let value = value.to_string();
                let field_values = if value == EMPTY_MAP_ENTRY {
                    Vec::with_capacity(0)
                } else {
                    if !value.contains(DATA_SPLITTER) {
                        let mut field_values = Vec::with_capacity(1);
                        field_values.push(value);

                        field_values
                    } else {
                        let values = value.split(DATA_SPLITTER).collect::<Vec<&str>>();
                        let amt = values.len();
                        let mut field_values = Vec::with_capacity(amt);
                        for (_, field_val) in values.iter().enumerate() {
                            let insert = field_val.to_string();

                            field_values.push(insert);
                        }

                        field_values
                    }
                };

                FieldEntry {
                    field_type: SubsectionType::Multimap,
                    field_values,
                }
            }

            _ => {
                panic!("Only map types may use this subroutine")
            }
        }
    }


    /// If the values are already split-up, use the subroutine instead
    fn field_values_to_multimap<T: ToString, R: ToString, V: AsRef<[R]>>(self, _: T, values: V) -> FieldEntry {
        match self {
            SubsectionType::Multimap => {
                let values = values.as_ref();
                let field_values = if values.is_empty() {
                    Vec::with_capacity(0)
                } else if values.len() == 1 {
                    let value = values[0].to_string();
                    if value == EMPTY_MAP_ENTRY {
                        Vec::with_capacity(0)
                    } else {
                        let mut ret = Vec::with_capacity(0);
                        ret.push(value);
                        ret
                    }
                } else {
                    let amt = values.len();
                    let mut field_values = Vec::with_capacity(amt);
                    for (_, field_val) in values.iter().enumerate() {
                        let insert = field_val.to_string();

                        field_values.push(insert);
                    }

                    field_values
                };

                FieldEntry {
                    field_type: SubsectionType::Multimap,
                    field_values,
                }
            }

            _ => {
                panic!("Only multimap types may use this subroutine")
            }
        }
    }
}

impl TryFrom<&'_ str> for SubsectionType {
    type Error = ConfigError;

    fn try_from(line: &'_ str) -> Result<Self, Self::Error> {
        if line.contains("as list") {
            Ok(SubsectionType::List)
        } else if line.contains("as map") {
            Ok(SubsectionType::Map)
        } else if line.contains("as multimap") {
            Ok(SubsectionType::Multimap)
        } else {
            Ok(SubsectionType::Null)
        }
    }
}

impl Display for Section {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let _ = writeln!(f, "[{}]", &self.name);
        for attr in &self.attributes {
            let _ = writeln!(f, "\t [Attribute] {} => {}", attr.0, attr.1);
        }

        for subsection in &self.sub_sections {
            let _ = writeln!(f, "\t{}", *subsection.1);
        }

        Ok(())
    }
}

impl Display for Subsection {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let _ = writeln!(f, "Subsection [name {} : parent {}]", &self.name, &self.parent);
        for line in self.fields.iter() {
            let _ = writeln!(f, "{} field", line.1.field_type);
        }

        Ok(())
    }
}

impl std::fmt::Debug for Subsection {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self)
    }
}

impl Display for SubsectionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let data = match self {
            SubsectionType::List => {
                "list"
            }

            SubsectionType::Map => {
                "map"
            }

            SubsectionType::Multimap => {
                "multimap"
            }

            SubsectionType::Null => {
                "undefined"
            }
        };
        write!(f, "{}", data)
    }
}

impl Clone for FieldEntry {
    fn clone(&self) -> Self {
        Self { field_type: self.field_type.clone(), field_values: self.field_values.clone() }
    }
}

impl Clone for Subsection {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            parent: self.parent.clone(),
            fields: self.fields.clone(),
            field_type: self.field_type.clone()
        }
    }
}

impl Clone for Section {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            sub_sections: self.sub_sections.clone(),
            attributes: self.attributes.clone(),
            notes: self.notes.clone()
        }
    }
}

impl Clone for ParsedConfig {
    fn clone(&self) -> Self {
        Self {
            sections: self.sections.clone(),
            needs_recompile: self.needs_recompile,
            compiled: self.compiled.clone()
        }
    }
}

impl Clone for ConfigFile {
    fn clone(&self) -> Self {
        Self { path: self.path.clone(), config: self.config.clone() }
    }
}