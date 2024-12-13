import os
import sys
import logging
from rich.console import Console
from rich.table import Table

# Rich console
console = Console()

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Rule Definitions
PASSWD_RULES = {
    "only_root_uid_0": {
        "rule": lambda line: ":" in line and line.split(":")[2].strip() == "0" and line.split(":")[0] != "root",
        "description": "Ensures only the 'root' user has UID 0."
    },
    "restricted_usernames": {
        "rule": lambda line: ":" in line and line.split(":")[0].strip() in ["guest", "test", "admin", "developer"],
        "description": "Flags restricted usernames such as 'guest', 'test', 'admin', and 'developer'."
    },
    "duplicate_users": {
        "rule": lambda line, seen=set(): line.split(":")[0] in seen or seen.add(line.split(":")[0]),
        "description": "Detects duplicate usernames in the passwd file."
    },
    "non_system_users_with_login": {
        "rule": lambda line: (
            ":" in line and int(line.split(":")[2].strip()) >= 1000 and line.split(":")[-1].strip() != "/sbin/nologin"
        ),
        "description": "Identifies non-system users (UID >= 1000) who have login access enabled."
    },
}

SUDOERS_RULES = {
    "no_full_permissions": {
        "rule": lambda line: "ALL=(ALL)" in line and not line.startswith("root"),
        "description": "Flags users or groups with 'ALL=(ALL)' permissions, except for the 'root' user."
    },
    "no_password_sudo": {
        "rule": lambda line: "NOPASSWD" in line,
        "description": "Detects users with 'NOPASSWD' configured, allowing passwordless sudo execution."
    },
    "no_wildcard_in_command": {
        "rule": lambda line: "NOPASSWD: ALL" in line and "*" in line,
        "description": "Identifies sudoers rules that use wildcard characters (*) in commands."
    },
    "non_root_sudo": {
        "rule": lambda line: "sudo" in line and not line.startswith("root"),
        "description": "Detects non-root users with sudo privileges."
    },
    "group_sudo_privileges": {
        "rule": lambda line: "%" in line and "ALL=(ALL)" in line,
        "description": "Flags groups (e.g., %admin) with broad sudo permissions."
    },
    "target_user_privileges": {
        "rule": lambda line: "ALL" in line and "(ALL)" not in line,
        "description": "Identifies users with permissions to execute commands as other users."
    },
}

SSHD_RULES = {

    "no_root_login": {
        "rule": lambda line: line.strip().startswith("PermitRootLogin") and "no" not in line,
    },
    "no_password_auth": {
        "rule": lambda line: line.strip().startswith("PasswordAuthentication") and "no" not in line,
    },
    "max_auth_tries": {
        "rule": lambda line: line.strip().startswith("MaxAuthTries") and int(line.split()[1]) > 3,
    },
    "permit_empty_passwords": {
        "rule": lambda line: line.strip().startswith("PermitEmptyPasswords") and "yes" in line,
    },
    
}


def scan_folder_for_files(path, target_file):
    target_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if target_file in file:
                target_files.append(os.path.join(root, file))
    return target_files


def is_comment_or_empty(line):
    """
    Checks if a line is a comment or empty, while allowing specific comments to be analyzed.
    """
    stripped_line = line.strip()
    if not stripped_line:
        return True  # Empty line
    # Skip lines that are comments, except those explicitly allowed for analysis
    if stripped_line.startswith("#"):
        # Allow comments that start with keywords (e.g., PermitRootLogin, PasswordAuthentication)
        allowed_keywords = ["PermitRootLogin", "PasswordAuthentication", "MaxAuthTries", "PermitEmptyPasswords"]
        for keyword in allowed_keywords:
            if stripped_line.lstrip("#").strip().startswith(keyword):
                return False
        return True  # Ignore all other comments
    return False


def analyze_file(file_path, rules):
    issues = []
    seen_users = set()
    with open(file_path, "r") as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if is_comment_or_empty(line):
                continue
            for rule_name, rule_data in rules.items():
                if rule_name == "duplicate_users":
                    if rule_data["rule"](line, seen_users):
                        issues.append((rule_name, line.strip()))
                elif rule_data["rule"](line):
                    issues.append((rule_name, line.strip()))
    return issues


def print_table(title, issues):
    table = Table(title=title, show_header=True, header_style="bold white")
    table.add_column("File Name", style="dim white", width=60)
    table.add_column("Rule", style="dim green", width=30)
    table.add_column("Violated Line", style="dim yellow", overflow="fold", width=80)

    for issue in issues:
        table.add_row(issue[0], issue[1], issue[2])

    console.print(table)


def analyze_and_report(folder_path, target_file, rules, title):
    files = scan_folder_for_files(folder_path, target_file)
    if not files:
        logging.info(f"No '{target_file}' files found.")
        return

    all_issues = []
    for file in files:
        logging.info(f"Analyzed file: {file}")
        issues = analyze_file(file, rules)
        if issues:
            for issue in issues:
                all_issues.append((os.path.basename(file), issue[0], issue[1]))
        else:
            logging.info(f"No rule violation found in {file}.")

    if all_issues:
        print_table(title, sorted(all_issues, key=lambda x: (x[0], x[1], x[2])))
    else:
        console.print("\n[bold green]No rule violations found.[/bold green]")


def show_help_from_file():
    """
    Reads the help.txt file from the current directory and displays its content in the terminal.
    """
    help_file_path = "help.txt"  # Help file name
    if os.path.exists(help_file_path):
        with open(help_file_path, "r") as help_file:
            console.print(help_file.read(), style="bold cyan")
    else:
        console.print("[bold red]help.txt file not found in the current directory![/bold red]")


def main_menu():
    """
    Main menu for the application.
    """
    while True:
        console.print("\n[bold green]Main Menu:[/bold green]")
        console.print("[1] Analyze 'passwd' files")
        console.print("[2] Analyze 'sudoers' files")
        console.print("[3] Analyze 'sshd_config' files")
        console.print("[4] Get 'Rule' Details")
        console.print("[5] Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            folder_path = input("Enter the folder path: ").strip()
            analyze_and_report(folder_path, "passwd", PASSWD_RULES, "Rule Violation Report (Passwd)")
        elif choice == "2":
            folder_path = input("Enter the folder path: ").strip()
            analyze_and_report(folder_path, "sudoers", SUDOERS_RULES, "Rule Violation Report (Sudoers)")
        elif choice == "3":
            folder_path = input("Enter the folder path: ").strip()
            analyze_and_report(folder_path, "sshd_config", SSHD_RULES, "Rule Violation Report (SSHD Config)")
        elif choice == "4":
            show_help_from_file()
        elif choice == "5":
            console.print("[bold red]Exiting...[/bold red]")
            break
        else:
            console.print("[bold red]Invalid choice. Please try again.[/bold red]")


if __name__ == "__main__":
    main_menu()
