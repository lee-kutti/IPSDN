#   python Model_Evaluation.py

from cgi import test
import timeit
import time
import pandas as pd
import numpy as np

from sklearn.preprocessing import minmax_scale
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import accuracy_score
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

X_train = pd.read_csv("Dataset/train_dataset.csv")
Y_train = X_train["class"]
del X_train["class"]
X_train.iloc[:] = minmax_scale(X_train.iloc[:])

X_test = pd.read_csv("Dataset/test_dataset.csv")
Y_test = X_test["class"]
del X_test["class"]

result = open('Txt_Files/evaluation_results.txt', "a+")


def testing(i):
    average_accuracy = 0.0

    for j in range(20):
        train = timeit.default_timer()
        mlp = MLPClassifier(hidden_layer_sizes=(i), activation="logistic", solver='adam', beta_1=0.9,beta_2=0.9,
                        learning_rate="constant", learning_rate_init=0.1, momentum=0.9)
        mlp.fit(X_train, Y_train.values.ravel())
        #print(mlp)
        #print(mlp.coefs_)

        train = timeit.default_timer() - train
        print("Training time :", train)
        test = timeit.default_timer()
        prediction = mlp.predict(X_test)
        test = timeit.default_timer() - test
        print("Testing time :", )

        # Evaluation
        c = confusion_matrix(Y_test, prediction)
        print(c)
        a = accuracy_score(Y_test, prediction) * 100

        average_accuracy += a

        print("Accuracy score: " + str(a) + "%")
        TN = c[0][0]
        FP = c[0][1]
        FN = c[1][0]
        TP = c[1][1]
        DR = float(TP)/(TP + FN) * 100  # Detection Rate
        FAR = float(FP)/(TP+FP) * 100  # False Alarm Rate
        print(DR, FAR)
        result.write("\n" + str(TN) + "," + str(FP) + "," + str(FN) + "," + str(TP) + "," + str(a) + ","
                    + str(train) + "," + str(test) + "," + str(DR) + "," + str(FAR))

        #print(classification_report(Y_test, prediction))

    average_accuracy /= 20
    print ("Average accuracy of 20 runtimes (MLP): %s" % average_accuracy)


testing(6)


def testing_svm():
    average_accuracy = 0.0

    for i in range(20): 
        train = timeit.default_timer()
        classifier = SVC(kernel='rbf', random_state=1, gamma='scale')

        classifier.fit(X_train, Y_train)
        #print(classifier)

        train = timeit.default_timer() - train
        print("Training time :", train)
        test = timeit.default_timer()
        prediction = classifier.predict(X_test)
        test = timeit.default_timer() - test

        print("Testing time :", )

        # Evaluation
        c = confusion_matrix(Y_test, prediction)
        print(c)
        a = accuracy_score(Y_test, prediction) * 100

        average_accuracy += a
        
        print("Accuracy score: " + str(a) + "%")
        TN = c[0][0]
        FP = c[0][1]
        FN = c[1][0]
        TP = c[1][1]

        DR = float(TP)/(TP + FN) * 100  # Detection Rate
        FAR = float(FP)/(TP+FP) * 100  # False Alarm Rate

        print(DR, FAR)
        result.write("\n" + str(TN) + "," + str(FP) + "," + str(FN) + "," + str(TP) + "," + str(a) + ","
                    + str(train) + "," + str(test) + "," + str(DR) + "," + str(FAR))

        #print(classification_report(Y_test, prediction))

    average_accuracy /= 20
    print ("Average accuracy of 20 runtimes (SVC): %s" % average_accuracy)


#testing_svm()

result.close()


#with src-port and dst-port:

print ("Dataset with source port and dest port:")

X_train = pd.read_csv("Dataset/train_dataset_with-src-dst-port.csv")
Y_train = X_train["class"]
del X_train["class"]
X_train.iloc[:] = minmax_scale(X_train.iloc[:])

X_test = pd.read_csv("Dataset/test_dataset_with-src-dst-port.csv")
Y_test = X_test["class"]
del X_test["class"]

result = open('Txt_Files/evaluation_results.txt', "a+")


#testing(6)

#testing_svm()

result.close()
