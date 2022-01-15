use jsonwebtoken::EncodingKey;
use octocrab::models::AppId;
use octocrab::Octocrab;
use std::sync::Arc;
use serde::Deserialize;
use crate::de::GithubString;

pub struct GithubHandler {
    inner: Arc<Octocrab>,
    organization_name: String
}

#[derive(Deserialize, Debug)]
struct Organization {
    login: GithubString,
    id: u64,
    node_id: GithubString,
    url: GithubString,
    repos_url: GithubString,
    events_url: GithubString,
    hooks_url: GithubString,
    issues_url: GithubString,
    members_url: GithubString,
    public_members_url: GithubString,
    avatar_url: GithubString,
    description: GithubString
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct Organizations {
    vals: Vec<Organization>
}

impl GithubHandler {
    pub async fn new(app_id: u64, private_key: &[u8], organization_name: impl Into<String>) -> Result<Self, anyhow::Error> {
        let key = EncodingKey::from_rsa_pem(private_key)?;
        let inner = octocrab::initialise(octocrab::OctocrabBuilder::default().app(AppId(app_id), key))?;
        Ok(Self { inner, organization_name: organization_name.into() })
    }

    pub async fn send_organization_invite(&self, user_id: String) -> Result<(), anyhow::Error> {
        let ref input = serde_json::json!({
            "org": self.organization_name.as_str(),
            "invitee-id": user_id,
            "role": "direct_member"
        });

        let path = self.build_path("/orgs/{org}/invitations");
        let _output: serde_json::Value = self.inner.post(path, Some(input)).await?;
        Ok(())
    }

    /*
        https://docs.github.com/en/rest/reference/orgs#remove-organization-membership-for-a-user
        Removes membership from the user_id. If an invitation is active, revokes the invitation
     */
    pub async fn delete_member(&self, user_id: impl AsRef<str>) -> Result<(), anyhow::Error> {
        let ref input = serde_json::json!({
            "org": self.organization_name.as_str(),
            "username": user_id.as_ref()
        });

        let path = self.build_path(&*format!("/orgs/{}/memberships/{}", self.organization_name.as_str(), user_id.as_ref()));
        let _output: serde_json::Value = self.inner.delete(path, Some(input)).await?;
        Ok(())
    }

    pub async fn list_organizations(&self) -> Result<Organizations, anyhow::Error> {
        let output: Organizations = self.inner.get("/organizations", None::<&()>).await?;
        Ok(output)
    }

    fn build_path(&self, input: &str) -> String {
        input.replace("{org}", self.organization_name.as_str())
    }
}