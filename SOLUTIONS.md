# Problems Encountered

---

## Issue: Encrypted Amount

### Problem Description
- **Unexpected Behavior**: The page threw a message saying that 'float' type was not valid to encrypt the amount.
- **Expected Behavior**: The encryption process should've worked without errors, encrypting the transaction amounts for storage in the database.
- **Discovery**: This issue was identified during testing when a new transaction was added to the database, and the application threw an error indicating that the `float` type was not valid for encryption.

### Root Cause Analysis
- **Cause**: The `amount` was being passed as a `float`, which is not a compatible type for encryption.
- **Incorrect Assumptions**: I incorrectly assumed that the `cryptography.Fernet` library could handle direct encryption of numerical values like floats without conversion to string format.
- **Dependencies Involved**: The `cryptography.Fernet` library, used for encryption, and SQLite3, used for storing the encrypted data, where the issue occurred.

### Resolution
- **Fix**: The `amount` value was explicitly converted to a string before encryption and back to a float after decryption.
- **Changes Made**: In the `save_transaction` function, the `amount` was converted to a string before calling the `encrypt_data` function. Similarly, in the `load_transactions` function, the decrypted data was converted back to a float for further processing.
- **Alternatives Considered**: One alternative considered was storing the amount without encryption; but, this was dismissed as it would compromise my marks for the encryption part :)

---

## Issue: IP Blocking
### Problem Description  
- **Unexpected Behavior**: The IP blocking feature unintentionally blocked my own IP during testing.  
- **Expected Behavior**: The application should've blocked only unauthorized IPs, not my own one.
- **Discovery**: This issue was identified during testing the application. Literally, I could not do anything so it was extremely necessary to edit it.

### Root Cause Analysis  
- **Cause**: The IP was set to block my own IP.
- **Incorrect Assumptions**: Assumed the local IP would ignore my own IP address.  
- **Dependencies Involved**: Flask request context and IP address handling.  

### Resolution  
- **Fix**: I commented the line that was in the guide. In this way I ensured that firewall guide was working and I could continue testing my application. 
- **Changes Made**: Updated BLOCKED_IPS = set(). Just to continue with my application.

---

## Issue: Password Validation  

### Problem Description  
- **Unexpected Behavior**: Users could register with weak passwords, compromising security and not working as a real world application.  
- **Expected Behavior**: Passwords should've followed requirements, such as minimum length and complexity (min. 1-8 character, etc...).  
- **Discovery**: During testing, a password like "123" was accepted (which professionally, is not advisable). 

### Root Cause Analysis  
- **Cause**: Password validation was not enforced in the signup form.  
- **Incorrect Assumptions**: Assumed users would create secure passwords without enforcement (but most of the time, users are more likely to create passwords that are easy to remember. Therefore, they get easier to guess).

### Resolution  
- **Fix**: Added password validation logic to enforce minimum length, use of uppercase letters, numbers, and special characters.  
- **Changes Made**: Updated the signup form and backend validation to reject weak passwords.  

---

## Issue: Login Redirect Order  

### Problem Description  
- **Unexpected Behavior**: The application was directly redirecting to the `index.html` page instead of prompting the user to log in first.
- **Expected Behavior**: The application should've initially displayed the login page (as most common personal applications).
- **Discovery**: This issue was encountered during testing when trying to access the app without being logged in, which redirected to the home page without showing the login form.

### Root Cause Analysis  
- **Cause**: The application's root route (`/`) was initially redirecting directly to `/index` without logging in as in application of the real world.
- **Incorrect Assumptions**: I just had not added the functionality properly
- **Dependencies**: Flask's session management, which tracks whether a user is logged in or not.

### Resolution  
- **Fix**: Adjusted the root route (`/`) logic to check for user authentication first. The login page is now shown instead of redirecting directly to the main page.
- **Changes Made**: Modified the root route to check if the session contains a `username` before redirecting.

---

## Issue: User Data Isolation

### Problem Description  
- **Unexpected Behavior**: User data was not being stored individually for each corresponding user, but everyone could see it.
- **Expected Behavior**: Each user should have their own isolated data stored in the session or database.
- **Discovery**: Encountered when I clicked on 'Get Transaction' logged as another user when I had logout from the previous one.

## Root Cause Analysis  
- **Cause**: The session management or database queries were not scoped to individual users, leading to shared data across sessions.
- **Incorrect Assumptions**: Assumed user-specific data would be automatically separated based on the session. But was a bit silly since they would be working with the same database.
- **Dependencies Involved**: Flask’s session management, database handling, and user authentication.

## Resolution  
- **Fix**: Implemented user-specific data isolation by associating data with each user ID.
- **Changes Made**: I updated the `save_transaction` function to store transactions with the `username` associated with the logged-in user. And modified the `load_transactions` function to filter transactions based on the logged-in user's `username`.
- **Alternatives Considered**: Storing data in separate tables for each user, but I didn't want to complicate myself.