import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib  # Import joblib for saving and loading models

# Paths to your folder and Excel sheet
nmap_folder = '/path/to/nmap/folder'  # Folder with Nmap output (filenames as MAC addresses)
excel_path = '/path/to/mac_device_os_info.xlsx'  # Excel file with MAC address, Device Type, OS Family

# Step 1: Read the Excel file (MAC Address, Device Type, OS Family)
df_labels = pd.read_excel(excel_path)

# Step 2: Load Nmap output files from the folder
nmap_data = []

for filename in os.listdir(nmap_folder):
    if filename.endswith(".txt"):  # Assuming your Nmap output files are .txt
        mac_address = filename.replace(".txt", "")
        file_path = os.path.join(nmap_folder, filename)

        # Read the Nmap output as text
        with open(file_path, 'r') as file:
            nmap_output = file.read()

        # Append MAC address and Nmap output
        nmap_data.append({
            'mac_address': mac_address,
            'nmap_output': nmap_output
        })

# Convert the list of dictionaries into a DataFrame
df_nmap = pd.DataFrame(nmap_data)

# Step 3: Merge the Nmap data with the ground truth data from the Excel file
df = pd.merge(df_nmap, df_labels, on='mac_address')

# Step 4: Preprocess the Nmap output (Text Vectorization)
# Use TF-IDF to vectorize the Nmap output text
vectorizer = TfidfVectorizer(max_features=500)  # Limiting to top 500 words for simplicity
X = vectorizer.fit_transform(df['nmap_output']).toarray()

# Step 5: Extract target labels (Device Type, OS Family)
y_device_type = df['DeviceType']  # Assuming 'DeviceType' column exists in the Excel sheet
y_os_family = df['OSFamily']      # Assuming 'OSFamily' column exists in the Excel sheet

# Step 6: Split data into training and testing sets for both Device Type and OS Family
X_train_device, X_test_device, y_train_device, y_test_device = train_test_split(X, y_device_type, test_size=0.3, random_state=42)
X_train_os, X_test_os, y_train_os, y_test_os = train_test_split(X, y_os_family, test_size=0.3, random_state=42)

# Step 7: Train classifiers for Device Type and OS Family

# Random Forest Classifier for Device Type
clf_device_type = RandomForestClassifier(n_estimators=100, random_state=42)
clf_device_type.fit(X_train_device, y_train_device)

# Random Forest Classifier for OS Family
clf_os_family = RandomForestClassifier(n_estimators=100, random_state=42)
clf_os_family.fit(X_train_os, y_train_os)

# Step 8: Save the trained models to disk
joblib.dump(clf_device_type, 'device_type_model.pkl')  # Save device type classifier
joblib.dump(clf_os_family, 'os_family_model.pkl')      # Save OS family classifier

print("Models saved successfully.")

# Step 9: Load the models (for future use)
clf_device_type_loaded = joblib.load('device_type_model.pkl')
clf_os_family_loaded = joblib.load('os_family_model.pkl')

print("Models loaded successfully.")

# Step 10: Predict on the test data using the loaded models
y_pred_device = clf_device_type_loaded.predict(X_test_device)
y_pred_os = clf_os_family_loaded.predict(X_test_os)

# Step 11: Evaluate the loaded models
accuracy_device = accuracy_score(y_test_device, y_pred_device)
accuracy_os = accuracy_score(y_test_os, y_pred_os)

print(f"Device Type Classification Accuracy: {accuracy_device * 100:.2f}%")
print(f"OS Family Classification Accuracy: {accuracy_os * 100:.2f}%")
