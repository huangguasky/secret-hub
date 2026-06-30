use crate::{EnvValue, EnvVariable, Result, SecretHubError};

pub fn parse_env(text: &str) -> Result<Vec<EnvVariable>> {
    let mut variables = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((raw_key, raw_value)) = assignment.split_once('=') else {
            return Err(SecretHubError::InvalidEnvLine(line_number));
        };

        let key = raw_key.trim();
        validate_key(key)?;

        let value = parse_value(raw_value.trim())?;
        variables.push(EnvVariable {
            key: key.to_string(),
            value: EnvValue::literal(value),
        });
    }
    Ok(variables)
}

pub fn render_env(variables: &[(String, String)]) -> String {
    let mut output = String::new();
    for (key, value) in variables {
        output.push_str(key);
        output.push('=');
        output.push_str(&render_value(value));
        output.push('\n');
    }
    output
}

pub fn validate_key(key: &str) -> Result<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(SecretHubError::InvalidEnvKey(key.to_string()));
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(SecretHubError::InvalidEnvKey(key.to_string()));
    }
    if chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric())) {
        return Err(SecretHubError::InvalidEnvKey(key.to_string()));
    }
    Ok(())
}

fn parse_value(value: &str) -> Result<String> {
    if value.len() >= 2 && value.starts_with('"') {
        let Some(end) = find_closing_double_quote(value) else {
            return Err(SecretHubError::InvalidEnvValue);
        };
        return unescape_double_quoted(&value[1..end]);
    }

    if value.len() >= 2 && value.starts_with('\'') {
        let Some(end) = value[1..].find('\'').map(|index| index + 1) else {
            return Err(SecretHubError::InvalidEnvValue);
        };
        return Ok(value[1..end].to_string());
    }

    Ok(strip_inline_comment(value).trim_end().to_string())
}

fn find_closing_double_quote(value: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, ch) in value.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some(index);
        }
    }
    None
}

fn unescape_double_quoted(value: &str) -> Result<String> {
    let mut output = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            return Err(SecretHubError::InvalidEnvValue);
        };
        match escaped {
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            '"' => output.push('"'),
            '\\' => output.push('\\'),
            other => {
                output.push('\\');
                output.push(other);
            }
        }
    }
    Ok(output)
}

fn strip_inline_comment(value: &str) -> &str {
    for (index, ch) in value.char_indices() {
        if ch == '#'
            && (index == 0
                || value[..index]
                    .chars()
                    .last()
                    .is_some_and(char::is_whitespace))
        {
            return &value[..index];
        }
    }
    value
}

fn render_value(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':'))
    {
        return value.to_string();
    }

    let mut output = String::from('"');
    for ch in value.chars() {
        match ch {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            other => output.push(other),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_env_lines() {
        let variables = parse_env(
            r#"
            # comment
            FOO=bar
            export API_KEY="abc 123"
            HASH=value#kept
            COMMENTED=value # dropped
            SINGLE='hello world'
            "#,
        )
        .unwrap();

        assert_eq!(variables.len(), 5);
        assert_eq!(variables[1].key, "API_KEY");
        assert!(matches!(
            &variables[1].value,
            EnvValue::Literal { value } if value == "abc 123"
        ));
        assert!(matches!(
            &variables[2].value,
            EnvValue::Literal { value } if value == "value#kept"
        ));
        assert!(matches!(
            &variables[3].value,
            EnvValue::Literal { value } if value == "value"
        ));
        assert!(matches!(
            &variables[4].value,
            EnvValue::Literal { value } if value == "hello world"
        ));
    }

    #[test]
    fn renders_values_that_need_quotes() {
        let variables = vec![
            ("PLAIN".to_string(), "abc-123".to_string()),
            ("SPACED".to_string(), "hello world".to_string()),
        ];

        assert_eq!(
            render_env(&variables),
            "PLAIN=abc-123\nSPACED=\"hello world\"\n"
        );
    }
}
