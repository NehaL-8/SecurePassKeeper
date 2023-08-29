#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <sstream>

using namespace std;

// Function to hash the passwords (You can use any secure hashing algorithm of your choice here)
string hashPassword(const string& password) {
    return password; // For simplicity, let's assume the password itself is the hash
}

// Function to generate a random password
string generatePassword() {
    const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    const int passwordLength = 12;

    string password;
    srand(static_cast<unsigned int>(time(nullptr)));
    for (int i = 0; i < passwordLength; ++i) {
        int index = rand() % charset.length();
        password += charset[index];
    }
    return password;
}

// Class representing a Password Manager
class PasswordManager {
private:
    string masterPassword;
    unordered_map<string, unordered_map<string, string>> passwords; // Changed to store username-password pairs

    // Function to load passwords from a file
    void loadPasswords() {
        ifstream file("passwords.txt");
        if (file.is_open()) {
            string line;
            while (getline(file, line)) {
                size_t pos1 = line.find(':');
                size_t pos2 = line.find(':', pos1 + 1);
                if (pos1 != string::npos && pos2 != string::npos) {
                    string website = line.substr(0, pos1);
                    string username = line.substr(pos1 + 1, pos2 - pos1 - 1);
                    string hashedPassword = line.substr(pos2 + 1);
                    passwords[website][username] = hashedPassword;
                }
            }
            file.close();
        }
    }

    // Function to save passwords to a file
    void savePasswords() {
        ofstream file("passwords.txt");
        if (file.is_open()) {
            for (const auto& websiteEntry : passwords) {
                const string& website = websiteEntry.first;
                const auto& usernamePasswords = websiteEntry.second;
                for (const auto& usernamePassword : usernamePasswords) {
                    const string& username = usernamePassword.first;
                    const string& password = usernamePassword.second;
                    file << website << ":" << username << ":" << password << endl;
                }
            }
            file.close();
        }
    }

    // Function to save the master password to a file
    void saveMasterPassword() {
        ofstream file("master_password.txt");
        if (file.is_open()) {
            file << masterPassword;
            file.close();
        }
        else {
            cout << "\033[1mError: Unable to save master password.\033[0m" << endl;
        }
    }

    // Function to check if a password is weak
    bool isWeakPassword(const string& password) {
        bool hasNumber = false;
        bool hasAlphabet = false;
        bool hasSpecialChar = false;

        for (char c : password) {
            if (isdigit(c)) {
                hasNumber = true;
            } else if (isalpha(c)) {
                hasAlphabet = true;
            } else if (!isalnum(c)) {
                hasSpecialChar = true;
            }
        }

        return !(hasNumber && hasAlphabet && hasSpecialChar);
    }

    // Function to update a weak password
    void updatePassword(const string& website, const string& username, const string& password) {
        passwords[website][username] = hashPassword(password);
        savePasswords();
        cout << "\033[1mPassword updated for\033[0m " << website << " \033[1mwith username\033[0m " << username << "." << endl;
    }

public:
    // Constructor
    PasswordManager() {
        loadPasswords();
    }

    // Function to set the master password
    void setMasterPassword() {
        string masterPassword;
        cout << "\033[1mPlease set your master password:\033[0m";
        getline(cin, masterPassword);
        masterPassword = hashPassword(masterPassword);
        this->masterPassword = masterPassword;
        saveMasterPassword();
        cout << "\033[1mMaster password set successfully.\033[0m" << endl;
    }

    // Function to add or update a password
    void addPassword(const string& website, const string& username, const string& password) {
        string hashedPassword = hashPassword(password);
        auto websiteEntry = passwords.find(website);
        if (websiteEntry != passwords.end() && websiteEntry->second.count(username)) {
            cout << "\033[1mPassword already saved for \033[0m" << website << "\033[1m with username\033[0m " << username << "." << endl;
            cout << "\033[1mDo you want to update the password? (yes/no):\033[0m ";
            string choice;
            getline(cin, choice);
            if (choice == "yes") {
                passwords[website][username] = hashedPassword;
                savePasswords();
                cout << "\033[1mPassword updated for\033[0m " << website << " \033[1mwith username\033[0m " << username << "." << endl;
                return;
            }
            else {
                return;
            }
        }
        passwords[website][username] = hashedPassword;
        savePasswords();
        cout << "\033[1mPassword saved for\033[0m " << website << " \033[1mwith username\033[0m " << username << "." << endl;
    }

    // Function to generate and save a password
    void generateAndSavePassword(const string& website, const string& username) {
        string password = generatePassword();
        addPassword(website, username, password);
        cout << "\033[1mGenerated Password:\033[0m " << password << endl;
    }

    // Function to delete a password
    void deletePassword(const string& website, const string& username) {
        if (passwords.count(website) && passwords[website].count(username)) {
            passwords[website].erase(username);
            savePasswords();
            cout << "\033[1mPassword deleted successfully.\033[0m" << endl;
        }
        else {
            cout << "\033[1mNo password found for the specified website and username.\033[0m" << endl;
        }
    }

    // Function to retrieve passwords based on website and/or username
    vector<tuple<string, string, string>> retrievePasswords(const string& website = "", const string& username = "") {
        vector<tuple<string, string, string>> credentials;
        for (const auto& websiteEntry : passwords) {
            const string& currWebsite = websiteEntry.first;
            if (website.empty() || currWebsite.find(website) != string::npos) {
                const auto& usernamePasswords = websiteEntry.second;
                for (const auto& usernamePassword : usernamePasswords) {
                    const string& currUsername = usernamePassword.first;
                    if (username.empty() || currUsername.find(username) != string::npos) {
                        const string& password = usernamePassword.second;
                        credentials.push_back(make_tuple(currWebsite, currUsername, password));
                    }
                }
            }
        }
        return credentials;
    }

    // Function to check and update weak passwords
    void checkAndUpdateWeakPasswords() {
        vector<tuple<string, string, string>> weakPasswords;
        for (const auto& websiteEntry : passwords) {
            const string& website = websiteEntry.first;
            const auto& usernamePasswords = websiteEntry.second;
            for (const auto& usernamePassword : usernamePasswords) {
                const string& username = usernamePassword.first;
                const string& password = usernamePassword.second;
                if (isWeakPassword(password)) {
                    weakPasswords.push_back(make_tuple(website, username, password));
                }
            }
        }

        if (weakPasswords.empty()) {
            cout << "\033[1mNo weak passwords found.\033[0m" << endl;
            return;
        }

        cout << "\033[1mWeak Passwords:\033[0m" << endl;
        for (const auto& weakPassword : weakPasswords) {
            cout << "Website: " << get<0>(weakPassword) << ", Username: " << get<1>(weakPassword) << ", Password: " << get<2>(weakPassword) << endl;
        }

        cout << "\033[1mPlease select a weak password to update (enter website and username):\033[0m" << endl;
        string website, username;
        cout << "\033[1mWebsite:\033[0m ";
        getline(cin, website);
        cout << "\033[1mUsername:\033[0m ";
        getline(cin, username);

        bool found = false;
        for (const auto& weakPassword : weakPasswords) {
            if (get<0>(weakPassword) == website && get<1>(weakPassword) == username) {
                found = true;
                break;
            }
        }

        if (!found) {
            cout << "\033[1mInvalid website or username. Exiting...\033[0m" << endl;
            return;
        }

        cout << "\033[1mEnter the new password (must contain at least one number, special character, and alphabet):\033[0m ";
        string newPassword;
        getline(cin, newPassword);

        if (isWeakPassword(newPassword)) {
            cout << "\033[1mInvalid password. Password must contain at least one number, special character, and alphabet.\033[0m" << endl;
            return;
        }

        updatePassword(website, username, newPassword);
        cout << "\033[1mPassword updated successfully.\033[0m" << endl;
    }

    // Function to update the master password
    void updateMasterPassword() {
        cout << "\033[1mPlease enter your old master password:\033[0m ";
        string oldPassword;
        getline(cin, oldPassword);
        if (!validateMasterPassword(oldPassword)) {
            cout << "\033[1mInvalid old master password. Exiting...\033[0m" << endl;
            return;
        }

        cout << "\033[1mPlease enter your new master password:\033[0m ";
        string newMasterPassword;
        getline(cin, newMasterPassword);

        cout << "\033[1mPlease confirm your new master password:\033[0m ";
        string confirmNewMasterPassword;
        getline(cin, confirmNewMasterPassword);

        if (newMasterPassword != confirmNewMasterPassword) {
            cout << "\033[1mNew master password and confirmation do not match. Exiting...\033[0m" << endl;
            return;
        }

        masterPassword = hashPassword(newMasterPassword);
        saveMasterPassword();
        savePasswords(); // Save the passwords again with the updated master password
        cout << "\033[1mMaster password updated successfully.\033[0m" << endl;
    }

    // Function to validate the master password
    bool validateMasterPassword(const string& password) {
        ifstream passwordFile("master_password.txt");
        if (passwordFile) {
            string storedMasterPassword;
            getline(passwordFile, storedMasterPassword);
            passwordFile.close();
            return (hashPassword(password) == storedMasterPassword);
        }
        else {
            cout << "\033[1mError: Unable to read master password file.\033[0m" << endl;
            return false;
        }
    }

    // Function to copy a string to the clipboard
    void copyToClipboard(const string& text) {
        stringstream cmd;
        cmd << "echo \"" << text << "\" | xclip -selection clipboard";
        system(cmd.str().c_str());
    }

    // Function to prompt the user to select an option (copy username or password) and copy it to the clipboard
    void copyCredentialToClipboard(const string& username, const string& password) {
        cout << "\033[1mSelect an option to copy to clipboard:\033[0m" << endl;
        cout << "1. Copy Username" << endl;
        cout << "2. Copy Password" << endl;
        cout << "0. Cancel" << endl;
        cout << "\033[1mChoose an option (0-2):\033[0m ";

        string option;
        getline(cin, option);

        if (option == "1") {
            copyToClipboard(username);
            cout << "\033[1mUsername copied to clipboard.\033[0m" << endl;
        }
        else if (option == "2") {
            copyToClipboard(password);
            cout << "\033[1mPassword copied to clipboard.\033[0m" << endl;
        }
        else if (option == "0") {
            cout << "\033[1mOperation canceled.\033[0m" << endl;
        }
        else {
            cout << "\033[1mInvalid option. Operation canceled.\033[0m" << endl;
        }
    }
};

// Function to display the credentials in a formatted table
void displayCredentialsTable(const vector<tuple<string, string, string>>& credentials) {
    cout << "---------------------------------------------------------------------------------------------------------------------------------------------" << endl;
    cout << "|                          SL No   |                    Website       |                    Username      |                     Password     |"<<endl; 
   cout << "---------------------------------------------------------------------------------------------------------------------------------------------" << endl;
    for (size_t i = 0; i < credentials.size(); ++i) {
        const auto& credential = credentials[i];
        cout << "|" << setw(33) << right << i + 1 << " |";
        cout << setw(33) << right << get<0>(credential) << " |";
        cout << setw(33) << right << get<1>(credential) << " |";
        cout << setw(33) << right << get<2>(credential) << " |";
        cout << endl;
    }
    cout << "---------------------------------------------------------------------------------------------------------------------------------------------" << endl;
}

// Function to display the title
void displayTitle() {
    cout << "---------------------------------------------------------------\033[1mSecurePassKeeper\033[0m---------------------------------------------------------------" << endl;
}

int main() {
    // Create an instance of the PasswordManager
    PasswordManager passwordManager;

    // Check if master password is set or not
    ifstream file("master_password.txt");
    if (!file) {
        passwordManager.setMasterPassword();
    }
    else {
        file.close();
        string enteredPassword;
        displayTitle();
        cout << "\033[1mPlease enter your master password:\033[0m ";
        getline(cin, enteredPassword);
        ifstream passwordFile("master_password.txt");
        if (passwordFile) {
            string storedMasterPassword;
            getline(passwordFile, storedMasterPassword);
            passwordFile.close();
            if (enteredPassword != storedMasterPassword) {
                cout << "\033[1mInvalid master password. Exiting...\033[0m" << endl;
                return 1;
            }
        }
        else {
            cout << "\033[1mError: Unable to read master password file.\033[0m" << endl;
            return 1;
        }
        cout << "\033[1mLogin successful!\033[0m" << endl;
    }

    // Main menu loop
    while (true) {
        cout << endl;
        cout << "1. \033[1mAdd or Update a Password\033[0m" << endl;
        cout << "2. \033[1mGenerate and Save a Password\033[0m" << endl;
        cout << "3. \033[1mRetrieve Passwords\033[0m" << endl;
        cout << "4. \033[1mCheck and Update Weak Passwords\033[0m" << endl;
        cout << "5. \033[1mDelete a Password\033[0m" << endl;
        cout << "6. \033[1mUpdate Master Password\033[0m" << endl;
        cout << "7. \033[1mExit\033[0m" << endl;
        cout << "\033[1mChoose an option (1-7):\033[0m ";

        string option;
        getline(cin, option);

        if (option == "1") {
            cout << "\033[1mEnter the website:\033[0m ";
            string website;
            getline(cin, website);

            cout << "\033[1mEnter the username:\033[0m ";
            string username;
            getline(cin, username);

            cout << "\033[1mEnter the password:\033[0m ";
            string password;
            getline(cin, password);

            passwordManager.addPassword(website, username, password);
            cout << "\033[1mPassword added or updated successfully.\033[0m" << endl;
            displayTitle();
        }
        else if (option == "2") {
            cout << "\033[1mEnter the website:\033[0m ";
            string website;
            getline(cin, website);

            cout << "\033[1mEnter the username:\033[0m ";
            string username;
            getline(cin, username);

            passwordManager.generateAndSavePassword(website, username);
            cout << "\033[1mGenerated and saved password successfully.\033[0m" << endl;
            displayTitle();
        }
        else if (option == "3") {
            cout << "\033[1mEnter the website (leave blank to display all):\033[0m ";
            string website;
            getline(cin, website);

            cout << "\033[1mEnter the username (leave blank to display all):\033[0m ";
            string username;
            getline(cin, username);

            vector<tuple<string, string, string>> credentials = passwordManager.retrievePasswords(website, username);
            cout << endl;
            cout << "\033[1mSearch results" << ((!website.empty() || !username.empty()) ? " for" : "") << "\033[0m ";
            if (!website.empty()) {
                cout << "website: " << website;
            }
            if (!website.empty() && !username.empty()) {
                cout << " and ";
            }
            if (!username.empty()) {
                cout << "username: " << username;
            }
            cout << ":" << endl;

            if (!credentials.empty()) {
                // Display credentials in table format
                displayCredentialsTable(credentials);

                // Prompt the user to select a credential and copy it to the clipboard
                cout << "\033[1mSelect a credential to copy to clipboard (enter SL No, or 0 to cancel):\033[0m ";
                string rowNumber;
                getline(cin, rowNumber);

                if (rowNumber != "0") {
                    int index = stoi(rowNumber) - 1;
                    if (index >= 0 && index < credentials.size()) {
                        const auto& credential = credentials[index];
                        const string& selectedUsername = get<1>(credential);
                        const string& selectedPassword = get<2>(credential);

                        passwordManager.copyCredentialToClipboard(selectedUsername, selectedPassword);
                    }
                    else {
                        cout << "\033[1mInvalid SL No. Operation canceled.\033[0m" << endl;
                    }
                }
                else {
                    cout << "\033[1mOperation canceled.\033[0m" << endl;
                }
            }
            else {
                cout << "\033[1mNo credentials found" << ((!website.empty() || !username.empty()) ? " for" : "") << "\033[0m ";
                if (!website.empty()) {
                    cout << "website: " << website;
                }
                if (!website.empty() && !username.empty()) {
                    cout << " and ";
                }
                if (!username.empty()) {
                    cout << "username: " << username;
                }
                cout << "." << endl;
            }
            displayTitle();
        }
        else if (option == "4") {
            passwordManager.checkAndUpdateWeakPasswords();
            displayTitle();
        }
        else if (option == "5") {
            cout << "\033[1mEnter the website:\033[0m ";
            string website;
            getline(cin, website);

            cout << "\033[1mEnter the username:\033[0m ";
            string username;
            getline(cin, username);

            passwordManager.deletePassword(website, username);
            displayTitle();
        }
        else if (option == "6") {
            passwordManager.updateMasterPassword();
            displayTitle();
        }
        else if (option == "7") {
            cout << "\033[1mExiting...\033[0m" << endl;
            break;
        }
        else {
            cout << "\033[1mInvalid option. Please choose a valid option.\033[0m" << endl;
        }
    }

    return 0;
} 
