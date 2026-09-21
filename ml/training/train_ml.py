from sklearn import tree
def DecisionTreeClassifer():
    for feature in features:
        X=[]    # X = [[1000,1000],[10,20]] (n_samples, n_features)
        Y=[]    # Y = [1000,1] (n_samples,"label") label is interger
        clf = tree.DecisionTreeClassifier()
        clf = clf.fit(X,Y)


def main():
    clf.predict([[2,2.]])   
    array([1])
    return