use std::collections::{HashMap, HashSet};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::StdResult;
use crate::entities::ImmutableFileNumber;

/// FileUri represents a file URI used to identify the file's location
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct FileUri(pub String);

impl From<FileUri> for String {
    fn from(file_uri: FileUri) -> Self {
        file_uri.0
    }
}

impl From<&FileUri> for String {
    fn from(file_uri: &FileUri) -> Self {
        file_uri.0.clone()
    }
}

/// TemplateVariable represents a variable in a template
pub type TemplateVariable = String;

/// TemplateValue represents a value in a template
pub type TemplateValue = String;

/// [TemplateUri] represents an URI pattern used to build a file's location
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct TemplateUri(pub String);

/// [MultiFilesUri] represents a unique location uri for multiple files
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MultiFilesUri {
    /// URI template representing several URI
    Template(TemplateUri),
}

impl MultiFilesUri {
    /// Extract a template from a list of URIs
    pub fn extract_template_from_uris(
        file_uris: Vec<String>,
        extractor: impl Fn(&str) -> StdResult<Option<String>>,
    ) -> StdResult<Option<TemplateUri>> {
        let mut templates = HashSet::new();
        for file_uri in file_uris {
            let template_uri = extractor(&file_uri)?;
            template_uri.map(|template| templates.insert(template));
        }

        if templates.len() > 1 {
            return Err(anyhow!("Multiple templates found in the file URIs"));
        }

        Ok(templates.into_iter().next().map(TemplateUri))
    }

    /// Expand the template to a list of file URIs
    pub fn expand_to_file_uris(
        &self,
        variables: Vec<HashMap<TemplateVariable, TemplateValue>>,
    ) -> StdResult<Vec<FileUri>> {
        Ok(variables
            .into_iter()
            .map(|variable| self.expand_to_file_uri(variable))
            .collect())
    }

    /// Expand the template to one file URI
    pub fn expand_to_file_uri(
        &self,
        variable: HashMap<TemplateVariable, TemplateValue>,
    ) -> FileUri {
        match self {
            MultiFilesUri::Template(template) => {
                let mut file_uri = template.0.clone();
                for (key, value) in variable {
                    file_uri = file_uri.replace(&format!("{{{key}}}"), &value);
                }

                FileUri(file_uri)
            }
        }
    }

    /// Expand the template to a file URI for a specific immutable file number
    ///
    /// Note: the template must contain the `{immutable_file_number}` variable
    pub fn expand_for_immutable_file_number(
        &self,
        immutable_file_number: ImmutableFileNumber,
    ) -> FileUri {
        self.expand_to_file_uri(HashMap::from([(
            "immutable_file_number".to_string(),
            format!("{immutable_file_number:05}"),
        )]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_template() {
        let file_uris = vec![
            "http://whatever/00001.tar.zst".to_string(),
            "http://whatever/00002.tar.zst".to_string(),
        ];
        fn extractor_returning_same_uri(_file_uri: &str) -> StdResult<Option<String>> {
            Ok(Some(
                "http://whatever/{immutable_file_number}.tar.zst".to_string(),
            ))
        }

        let template =
            MultiFilesUri::extract_template_from_uris(file_uris, extractor_returning_same_uri)
                .unwrap();

        assert_eq!(
            template,
            Some(TemplateUri(
                "http://whatever/{immutable_file_number}.tar.zst".to_string()
            ))
        );
    }

    #[test]
    fn returns_error_with_multiple_templates() {
        let file_uris = vec![
            "http://whatever/00001.tar.zst".to_string(),
            "http://00002.tar.zst/whatever".to_string(),
        ];
        fn extractor_returning_different_uri(file_uri: &str) -> StdResult<Option<String>> {
            Ok(Some(file_uri.to_string()))
        }

        MultiFilesUri::extract_template_from_uris(file_uris, extractor_returning_different_uri)
            .expect_err(
                "Should return an error when multiple templates are found in the file URIs",
            );
    }

    #[test]
    fn expand_multi_file_template_to_one_file_uri() {
        let template = MultiFilesUri::Template(TemplateUri(
            "http://whatever/{var1}-{var2}.tar.zst".to_string(),
        ));

        assert_eq!(
            template.expand_to_file_uri(HashMap::from([
                ("var1".to_string(), "00001".to_string()),
                ("var2".to_string(), "abc".to_string()),
            ]),),
            FileUri("http://whatever/00001-abc.tar.zst".to_string()),
        );

        assert_eq!(
            template.expand_to_file_uri(HashMap::from([
                ("var1".to_string(), "00001".to_string()),
                ("var2".to_string(), "def".to_string()),
            ]),),
            FileUri("http://whatever/00001-def.tar.zst".to_string()),
        );

        assert_eq!(
            template.expand_to_file_uri(HashMap::from([
                ("var1".to_string(), "00002".to_string()),
                ("var2".to_string(), "def".to_string()),
            ]),),
            FileUri("http://whatever/00002-def.tar.zst".to_string()),
        );
    }

    #[test]
    fn expand_multi_file_template_to_immutable_file_number() {
        let template = MultiFilesUri::Template(TemplateUri(
            "http://whatever/{immutable_file_number}.tar.zst".to_string(),
        ));

        assert_eq!(
            template.expand_for_immutable_file_number(6),
            FileUri("http://whatever/00006.tar.zst".to_string()),
        );

        assert_eq!(
            template.expand_for_immutable_file_number(15329),
            FileUri("http://whatever/15329.tar.zst".to_string()),
        );

        assert_eq!(
            template.expand_for_immutable_file_number(199999),
            FileUri("http://whatever/199999.tar.zst".to_string()),
        );
    }

    #[test]
    fn expand_multi_file_template_to_multiple_file_uris() {
        let template = MultiFilesUri::Template(TemplateUri(
            "http://whatever/{var1}-{var2}.tar.zst".to_string(),
        ));
        let variables = vec![
            HashMap::from([
                ("var1".to_string(), "00001".to_string()),
                ("var2".to_string(), "abc".to_string()),
            ]),
            HashMap::from([
                ("var1".to_string(), "00001".to_string()),
                ("var2".to_string(), "def".to_string()),
            ]),
            HashMap::from([
                ("var1".to_string(), "00002".to_string()),
                ("var2".to_string(), "def".to_string()),
            ]),
        ];

        let expanded_file_uris = template.expand_to_file_uris(variables).unwrap();
        assert_eq!(
            vec![
                FileUri("http://whatever/00001-abc.tar.zst".to_string()),
                FileUri("http://whatever/00001-def.tar.zst".to_string()),
                FileUri("http://whatever/00002-def.tar.zst".to_string()),
            ],
            expanded_file_uris,
        );
    }
}
