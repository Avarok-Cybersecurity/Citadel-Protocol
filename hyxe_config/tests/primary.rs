#[cfg(test)]
mod tests {

    use hyxe_config::prelude::*;
    use hyxe_config::config_handler::SubsectionType;
    use std::future::Future;

    fn block_on<F: Future>(future: F) {
        std::env::set_var("RUST_LOG", "info");
        env_logger::init();
        tokio::runtime::Runtime::new().unwrap().block_on(future);
    }

    #[test]
    fn primary() {
        block_on(test_both())
    }

    async fn test_both() {
        let _ = async_create_file().await;
        let _ = async_load_file().await;
    }

    #[test]
    fn load_file() {
        block_on(async_load_file());
    }

    async fn async_load_file() {
        match ConfigFile::load_in_default_dir("test2").await {
            Ok(mut file) => {
                println!("Config file loaded successfully!");
                println!("{}", file.get_compiled_text().unwrap());

                file.save().await.unwrap();
            }

            Err(err) => {
                println!("Error: {}", err.to_string());
            }
        };
    }


    #[test]
    fn create_file() {
        block_on(async_create_file());
    }

    async fn async_create_file() {
        match ConfigFile::create_in_default_dir("test2", None).await {
            Ok(mut file) => {
                println!("Config file created successfully!");


                assert!(file.add_section("adefault2").is_ok());
                assert!(file.add_subsection("adefault2", "inner", SubsectionType::Multimap).is_ok());
                assert!(file.add_multimap_field("adefault2", "inner", "multimap", ["0", "1", "2", "3"]).is_ok());
                assert!(file.remove_field_value("adefault2", "inner", "multimap", "2").is_ok());
                assert_eq!(file.remove_field_values("adefault2", "inner", "multimap", ["0", "1", "3"]).unwrap(), 3);
                assert!(file.add_subsection("adefault2", "ainner", SubsectionType::List).is_ok());
                assert!(file.add_list_field("adefault2", "ainner", "mylist").is_ok());
                assert!(file.add_list_field("adefault2", "ainner", "mylist2").is_ok());
                assert!(file.add_list_field("adefault2", "ainner", "mylist3").is_ok());
                assert!(file.add_list_field("adefault2", "ainner", "mylist4").is_ok());
                assert_eq!(file.remove_list_fields("adefault2", "ainner", ["mylist3", "mylist"]).unwrap(), 2);

                assert!(file.add_subsection("default", "zemp-multimap", SubsectionType::Multimap).is_ok());
                assert!(file.add_multimap_field("default", "zemp-multimap", "values",["zhello world!!!!", "Another value"]).is_ok());

                assert!(file.add_subsection("default", "temp", SubsectionType::Null).is_ok());
                assert!(file.add_list_field("default", "temp", "Entry 1").is_ok());
                assert!(file.add_list_field("default", "temp", "hello world2!!!!").is_ok());
                assert!(file.add_list_field("default", "temp", "hello world3!!!!").is_ok());

                assert!(file.add_subsection("default", "map0", SubsectionType::Map).is_ok());
                assert!(file.add_map_field("default", "map0", "field_name", "field value").is_ok());
                assert!(file.add_map_field("default", "map0", "field_name2", "field value2").is_ok());
                assert!(file.remove_field_value("default", "map0", "field_name", "field value").is_ok());

                assert!(file.recompile().is_ok());

                println!("{}", file.get_compiled_text().unwrap());
                file.save().await.and_then(|_| {
                    Ok(())
                }).map_err(|err| {
                    println!("ERR: {}", err.to_string());
                }).and_then(|_| {
                    Ok(())
                }).unwrap();

                file.save().await.unwrap();
            }

            Err(err) => {
                println!("Error: {}", err.to_string());
            }
        };
    }
}