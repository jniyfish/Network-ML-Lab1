import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn import datasets
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn import tree
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn import metrics

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

x_train, x_test, y_train, y_test = train_test_split(x,y, test_size=0.3, random_state=0)

classifier = tree.DecisionTreeClassifier(criterion = 'entropy' , max_depth=10, random_state=0)
classifier.fit(x_train, y_train)
tree.plot_tree(classifier)

predict_y = classifier.predict(x_test)

accuracy = metrics.accuracy_score(y_test, predict_y)
print(accuracy)
