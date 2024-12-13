# Unix File Analysis

This project analyzes important system files (`passwd`, `sudoers`, `sshd_config`) to detect potential misconfigurations or violations based on predefined rules.

## Features
- Analyze `passwd` files for:
  - Restricted usernames.
  - Duplicate usernames.
  - Non-system users with login access.
  - Root UID misconfigurations.

- Analyze `sudoers` files for:
  - Broad permissions for non-root users.
  - Wildcards in commands.
  - Passwordless sudo execution.

- Analyze `sshd_config` files for:
  - Unsafe `PermitRootLogin` settings.
  - Insecure `PasswordAuthentication` settings.
  - Excessive authentication attempts (`MaxAuthTries`).
  - Permitting empty passwords.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/unix-file-analysis.git
   ```
2. Navigate to the project directory:
   ```bash
   cd unix-file-analysis
   ```
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the script and follow the menu options:
```bash
python unix_file_analysis.py
```

### Command-Line Arguments
- `--help`: Displays detailed rule descriptions.
- Example:
  ```bash
  python unix_file_analysis.py --help
  ```

## Project Structure
```
.
├── unix_file_analysis.py   # Main script
├── help.txt                # Detailed rule descriptions
└── README.md               # Project documentation
```

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License.
