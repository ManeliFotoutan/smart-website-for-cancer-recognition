import pickle


with open('MLModel/model.pkl', 'rb') as f:
    model = pickle.load(f)

def cancer_prediction(features):
    prediction = model.predict([features])
    if prediction[0]:
        return "benign"
    return "malignant"