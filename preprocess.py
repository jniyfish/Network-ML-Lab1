import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn import datasets
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn import tree
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn import metrics
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import KFold


names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","target"]


df = pd.read_csv('corrected', names=names, low_memory=False)

df['num_outbound_cmds']
for i in df['num_outbound_cmds']:
    if i!=0:
        print("one")

#remove redundant features (this column are all zeros)
print(df.shape)
df['num_outbound_cmds'].value_counts()
df.drop('num_outbound_cmds', axis=1, inplace=True)

#remove duplicates
df.drop_duplicates(subset=None, keep='first', inplace=True)
print(df.shape)

df = df.replace("back.", 2)
df = df.replace("buffer_overflow.",3)
df = df.replace("ftp_write.",4)
df = df.replace("guess_passwd.",4)
df = df.replace("imap.",4)
df = df.replace("ipsweep.",1)
df = df.replace("land.",2)
df = df.replace("loadmodule.",3)
df = df.replace("multihop.",4)
df = df.replace("neptune.",2)
df = df.replace("nmap.",1)
df = df.replace("perl.",3)
df = df.replace("phf.",4)
df = df.replace("pod.",2)
df = df.replace("portsweep.",1)
df = df.replace("rootkit.",3)
df = df.replace("satan.",1)
df = df.replace("smurf.",2)
df = df.replace("spy.",4)
df = df.replace("teardrop.",2)
df = df.replace("warezclient.",4)
df = df.replace("warezmaster.",4)

#proto type
df = df.replace("icmp",1)
df = df.replace("udp",2)
df = df.replace("tcp",3)

#service
df = df.drop('service', 1)

ptype = pd.factorize(df['protocol_type'])
flag = pd.factorize(df['flag'])
tar = pd.factorize(df['target'])

df['protocol_type'] = ptype[0]
df['flag'] = flag[0]
df['target'] = tar[0]


features = list(df.columns[0:39])

x = df[features]
y = df["target"]

xnmp=x.to_numpy()
xnmp = np.array(xnmp, dtype=np.float64)
ynmp=y.to_numpy()
ynmp = np.array(ynmp, dtype=np.float64)

kf = KFold(n_splits=3)
kf.get_n_splits(xnmp)
time = 0
for train_index, test_index in kf.split(xnmp):
    time = time + 1
    x_train, x_test = xnmp[train_index], xnmp[test_index]
    y_train, y_test = ynmp[train_index], ynmp[test_index]
    print("-----Time: "+ str(time) + "  Decision Tree-----")
    #decision tree
    classifier = tree.DecisionTreeClassifier(criterion = 'entropy' , max_depth=10, random_state=0)
    classifier.fit(x_train, y_train)
    tree.plot_tree(classifier)
    predict_y = classifier.predict(x_test)
    accuracy = metrics.accuracy_score(y_test, predict_y)
    cm = confusion_matrix(y_test, predict_y)
    print("Accuracy: "+ str(accuracy))
    recall = cm[1,1]/(cm[0,1]+cm[1,1])  #true positives/ false negatives + true positives
    print("Recall is : "+ str(recall))
    precision = cm[1,1]/(cm[1,0]+cm[1,1])  #Precision=true positives/ false positives + true positives
    print("Precision is: "+ str(precision))
    f1_score = 2*((precision*recall)/(precision+recall)) #F1 = 2 * (precision * recall) / (precision + recall)
    print("F1 is: "+ str(f1_score))


    #Random Forest
    from sklearn.ensemble import RandomForestClassifier
    print("-----Time: "+ str(time) + "  Random Forest-----")
    rforest = RandomForestClassifier(n_estimators=100, random_state=0)
    rforest.fit(x_train, y_train)
    rforest_pred = rforest.predict(x_test)
    rforestcm = confusion_matrix(y_test, rforest_pred)
    print("Accuracy: "+ str(metrics.accuracy_score(y_test, rforest_pred)))
    recall = rforestcm[1,1]/(rforestcm[0,1]+rforestcm[1,1])  #true positives/ false negatives + true positives
    print("Recall is : "+ str(recall))
    precision = rforestcm[1,1]/(rforestcm[1,0]+rforestcm[1,1])  #Precision=true positives/ false positives + true positives
    print("Precision is: "+ str(precision))
    f1_score = 2*((precision*recall)/(precision+recall)) #F1 = 2 * (precision * recall) / (precision + recall)
    print("F1 is: "+ str(f1_score))


    #knn
    print("-----Time: "+ str(time) + "  KNN-----")
    from sklearn.neighbors import KNeighborsClassifier
    #for i in range (100)
    #nn = KNeighborsClassifier(n_neighbors= 5)
    knn = KNeighborsClassifier(n_neighbors= 5)
    knn.fit(x_train,y_train)
    knn_pred = knn.predict(x_test)
    print("Accuracy: "+ str(metrics.accuracy_score(y_test, knn_pred)))

    knncm = confusion_matrix(y_test, knn_pred)
    print("Accuracy: "+ str(metrics.accuracy_score(y_test, knn_pred)))
    recall = knncm[1,1]/(knncm[0,1]+knncm[1,1])  #true positives/ false negatives + true positives
    print("Recall is : "+ str(recall))
    precision = knncm[1,1]/(knncm[1,0]+knncm[1,1])  #Precision=true positives/ false positives + true positives
    print("Precision is: "+ str(precision))
    f1_score = 2*((precision*recall)/(precision+recall)) #F1 = 2 * (precision * recall) / (precision + recall)
    print("F1 is: "+ str(f1_score))

