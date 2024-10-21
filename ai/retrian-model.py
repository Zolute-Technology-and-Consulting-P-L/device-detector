import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Paths to your folder and Excel sheet for new data
new_nmap_folder = '/path/to/new/nmap/folder'  # Folder with new Nmap output (filenames as MAC addresses)
new_excel_path = '/path/to/new_mac_device_os_info.xlsx'  # Excel file with new MAC address, Device Type, OS Family

# Load old models if they exist, else initialize new models
try:
    clf_device_type = joblib.load('device_type_model.pkl')
    clf_os_family = joblib.load('os_family_model.pkl')
    print("Old models loaded successfully.")
except FileNotFoundError:
    clf_device_type = RandomForestClassifier(n_estimators=100, random_state=42)
    clf_os_family = RandomForestClassifier(n_estimators=100, random_state=42)
    print("No existing models found. Starting with new models.")

# Step 1: Load old and new data from the Excel sheets and Nmap folders
old_excel_path = '/path/to/mac_device_os_info.xlsx'  # Previous Excel file path

# Load old data
old_df_labels = pd.read_excel(old_excel_path)

# Load new data
new_df_labels = pd.read_excel(new_excel_path)

# Load new Nmap output files from the folder
new_nmap_data = []
for filename in os.listdir(new_nmap_folder):
    if filename.endswith(".txt"):  # Assuming your Nmap output files are .txt
        mac_address = filename.replace(".txt", "")
        file_path = os.path.join(new_nmap_folder, filename)
        with open(file_path, 'r') as file:
            nmap_output = file.read()
        new_nmap_data.append({
            'mac_address': mac_address,
            'nmap_output': nmap_output
        })

# Convert new Nmap data into a DataFrame
df_new_nmap = pd.DataFrame(new_nmap_data)

# Step 2: Merge old and new Nmap data with their corresponding labels
df_old_nmap = pd.DataFrame({
    'mac_address': old_df_labels['mac_address'],
    'nmap_output': old_df_labels['nmap_output']
})

# Merge old and new data
df_combined_labels = pd.concat([old_df_labels, new_df_labels], ignore_index=True)
df_combined_nmap = pd.concat([df_old_nmap, df_new_nmap], ignore_index=True)

# Step 3: Preprocess combined Nmap output (Text Vectorization)
vectorizer = TfidfVectorizer(max_features=500)
X_combined = vectorizer.fit_transform(df_combined_nmap['nmap_output']).toarray()

# Step 4: Extract target labels (Device Type, OS Family)
y_combined_device_type = df_combined_labels['DeviceType']
y_combined_os_family = df_combined_labels['OSFamily']

# Step 5: Split combined data into training and testing sets
X_train_device, X_test_device, y_train_device, y_test_device = train_test_split(
    X_combined, y_combined_device_type, test_size=0.3, random_state=42)

X_train_os, X_test_os, y_train_os, y_test_os = train_test_split(
    X_combined, y_combined_os_family, test_size=0.3, random_state=42)

# Step 6: Retrain classifiers for Device Type and OS Family

# Retrain Random Forest Classifier for Device Type
clf_device_type.fit(X_train_device, y_train_device)

# Retrain Random Forest Classifier for OS Family
clf_os_family.fit(X_train_os, y_train_os)

# Step 7: Save the updated models to disk
joblib.dump(clf_device_type, 'device_type_model.pkl')  # Save updated device type classifier
joblib.dump(clf_os_family, 'os_family_model.pkl')      # Save updated OS family classifier

print("Updated models saved successfully.")

# Step 8: Evaluate the updated models on the test data
y_pred_device = clf_device_type.predict(X_test_device)
y_pred_os = clf_os_family.predict(X_test_os)

# Step 9: Evaluate the updated models
accuracy_device = accuracy_score(y_test_device, y_pred_device)
accuracy_os = accuracy_score(y_test_os, y_pred_os)

print(f"Updated Device Type Classification Accuracy: {accuracy_device * 100:.2f}%")
print(f"Updated OS Family Classification Accuracy: {accuracy_os * 100:.2f}%")
