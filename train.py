import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import pickle
import os

# Load dataset
data = pd.read_csv("data/output.csv")

# Encode target variable
le = LabelEncoder()
data['diseases'] = le.fit_transform(data['diseases'])

# Split data
X = data.drop('diseases', axis=1)
y = data['diseases']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Build model
model = tf.keras.Sequential([
    tf.keras.layers.Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
    tf.keras.layers.Dropout(0.3),
    tf.keras.layers.Dense(64, activation='relu'),
    tf.keras.layers.Dense(len(le.classes_), activation='softmax')
])

model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=50, validation_data=(X_test, y_test))

# Ensure models directory exists
os.makedirs("models", exist_ok=True)

# Save the model
model.save("models/diagnosis_model.h5")

# Save the label encoder
with open("models/label_encoder.pkl", "wb") as f:
    pickle.dump(le, f)

# Save the scaler
with open("models/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

# Save column names
with open("models/X_columns.pkl", "wb") as f:
    pickle.dump(X.columns.tolist(), f)

print("✅ Training complete. Model and preprocessing tools saved.")
