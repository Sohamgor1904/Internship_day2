import pickle  
f = open('./data/models/metadata.pkl', 'rb')  
feature_names = pickle.load(f)  
print(feature_names) 
