#[macro_use]
extern crate magic_crypt;

use std::{
    fs::File,
    io::{BufReader, Read, Write, BufRead}, collections::HashMap, env
};

use magic_crypt::MagicCryptTrait;

fn main() {
    let args: Vec<String> = env::args().collect();
    for argument in &args {
        println!("argument: {}", argument);
    }
    if args.len() >= 2 {
        match args[1].as_str() {
            "help" => {
                print_help();
            }
            "add" => {
                println!("using command [{}]", "add");
                if args.len() >= 5 {
                    let path = &args[2];
                    let adress = &args[3];
                    let password = &args[4];

                    println!("Adding password {} to the adress {}, to file {}", path, adress, password);
                    add_password(&path, &adress, &password)
                } else {
                    println!("Not enough arguments given, need {} but only found {}. Command requires 'pathname', 'adress', 'password'.", 5-2, args.len()-2);
                }
            },
            "get" => {
                println!("using command [{}]", "get");
                if args.len() >= 4 {
                    let path = &args[2];
                    let adress = &args[3];

                    println!("Finding password for adress {} in file {}", adress, path);
                    let password = get_password(path, adress);
                    match password {
                        Some(value) => println!("Found password : [{}]", decrypt(&value)),
                        None => println!("Could not find adress {}", adress),
                    }
                } else {
                    println!("Not enough arguments given, need {} but only found {}. Command requires 'pathname', 'adress'.", 4-2, args.len() - 2);
                }
            }
            _ => println!("{}", "command not found"),   
        }
    } else {
        println!("No arguments found");
        print_help();
    }

}

fn print_help() {
    println!("list of commands: ");
    println!("\t[add] : Add a password to a file. Encrypts your password. params: 'filepath', 'adress', 'password';");
    println!("\t[get] : Get a password from a file. Decrypts your password. params: 'filepath', 'adress';");
}

fn get_password(filepath: &String, adress: &String) -> Option<String> {
    let passwords = get_password_pairs(&filepath);
    match passwords.get(adress) {
        Some(value) => Some(String::clone(value)),
        None => None,
    }
    
}

fn get_password_pairs(filepath: &String) -> HashMap<String, String> {
    match get_passwords_vector(&filepath) {
        Ok(vector) => {
            let mut pairs: HashMap<String, String> = HashMap::new();
            for (index, mut value) in vector.iter().enumerate() {
                //println!("Succesfull vecotor gotten! [{}] ==> {}", index, value);
                let replace = value.replace("{", "").replace("}", "").replace("\"", "").replace(",", "").replace(" ", "");
                value = &replace;
                let splitter = value.split(":");
                let vals: Vec<&str> = splitter.collect();
                pairs.insert(vals[0].to_string(), vals[1].to_string());
            }
            pairs
        },
        Err(err) => {
            println!("Error on trying to get password vec: {}", &err);
            HashMap::new()
        },
    }
}

fn add_password(filepath: &String, adress: &String, password: &String) {
    match add_password_file(&filepath, adress, &encrypt(&password)) {
        Ok(resp) => println!("Written to file with. New Length: {}", resp),
        Err(err) => eprintln!("Could not write to file! {}", err),
    }
}

fn encrypt(password: &String) -> String {
    let mcrypt = new_magic_crypt!("magickey", 256); //Creates an instance of the magic crypt library/crate.
    mcrypt.encrypt_str_to_base64(password)
}

fn decrypt(encrypted: &String) -> String {
    let mcrypt = new_magic_crypt!("magickey", 256); //Creates an instance of the magic crypt library/crate.
                                                    //Decrypts the string so we can read it.
    match mcrypt.decrypt_base64_to_string(encrypted) {
        Ok(value) => {value},
        Err(err) => {err.to_string()},
    }
}

fn _open_file_or_create(filepath: &String) -> std::io::Result<File> {
    match File::open(filepath) {
        Ok(file) => Ok(file),
        Err(_) => File::create(filepath),
    }
}

fn read_file(filepath: &String) -> std::io::Result<String> {
    let file = File::open(filepath)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;
    Ok(contents)
}

fn _write_file(filepath: &String, content: &String) -> Result<usize, std::io::Error> {
    let mut file = File::create(filepath)?;
    let buf = content.as_bytes();
    file.write(buf)
}

fn _append_file(filepath: &String, content: &String) -> Result<usize, std::io::Error> {
    let file_content = read_file(filepath)?;
    let mut file = File::create(filepath)?;
    let wr = file_content + content + &String::from("\n");
    let buf = wr.as_bytes();
    file.write(buf)
}

fn add_password_file(filepath: &String, adress: &String, password: &String) -> Result<usize, std::io::Error> {
    let file_content = match read_file(filepath) {
        Ok(value) => value,
        Err(_) => {
            println!("Created file: {}", filepath);
            String::from("")    
        },
    };
    let comma = if file_content != "" { ", \n" } else { "" };
    let mut file = File::create(filepath)?;
    let wr = file_content + comma + "{ \"" + adress + "\" : \"" + password + &String::from("\" }");
    let buf = wr.as_bytes();
    file.write(buf)
}

fn _get_passwords_string(filepath: &String) -> String {
    match read_file(filepath) {
        Ok(value) => value,
        Err(err) => {
            println!("Error: {}", err);
            String::from("")    
        },
    }
}

fn get_passwords_vector (filepath: &String) -> Result<Vec<String>, std::io::Error> {
    let f_result = File::open(filepath);
    match f_result {
        Ok(file) => {
            BufReader::new(file).lines().collect()
        },
        Err(err) => {
            println!("Failed to open file! {}", err);
            Err(err)
        },
    }

}