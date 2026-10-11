#2.kısım
import os
os.environ["OMP_NUM_THREADS"] = "1"
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import warnings
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, silhouette_score

warnings.filterwarnings("ignore")
#
def yeni_sistemi_egit():
    base_path = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(base_path, "modeller")

    print(" Yeni ön işlenmiş veriler yükleniyor...")
    try:
        X_train, y_train = joblib.load(os.path.join(model_dir, "yeni_egitim_verisi.pkl"))
        X_test, y_test = joblib.load(os.path.join(model_dir, "yeni_test_verisi.pkl"))
        print(" Veriler yüklendi.")
    except Exception as e:
        print(f"HATA: {e}")
        return

 #5.kısım
    print("\n Optimal K seçiliyor...")
    normal_data = X_train[y_train == 0]
    normal_sample = normal_data.sample(min(3000, len(normal_data)), random_state=42)
    best_k, best_score = 2, -1
    for k in range(2, 9):
        km_tmp = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = km_tmp.fit_predict(normal_sample)
        score = silhouette_score(normal_sample, labels)
        print(f"    k={k} -> silhouette={score:.4f}")
        if score > best_score:
            best_score, best_k = score, k

    print(f" Seçilen K: {best_k}")
    kmeans = KMeans(n_clusters=best_k, random_state=42, n_init=10)
    kmeans.fit(normal_data)

  
    dist_train = np.min(kmeans.transform(normal_data), axis=1)
    threshold = np.percentile(dist_train, 95)
    
    
    kmeans_pred = (np.min(kmeans.transform(X_test), axis=1) > threshold).astype(int)

    
    print("\n Stacking modeli eğitiliyor...")
    stack = StackingClassifier(
        estimators=[('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                    ('lr', LogisticRegression(max_iter=1000))],
        final_estimator=LogisticRegression()
    )
    stack.fit(X_train, y_train)
    stack_pred = stack.predict(X_test)

    # --- HİBRİT KARAR VE RAPOR ---
    final_pred = np.logical_or(stack_pred, kmeans_pred).astype(int)
    
    print("\n" + "="*45)
    print(f"Accuracy: %{accuracy_score(y_test, final_pred)*100:.2f}")
    print(classification_report(y_test, final_pred))

    # Confusion Matrix
    cm = confusion_matrix(y_test, final_pred)
    plt.figure(figsize=(7, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges')
    plt.savefig("yeni_performans_matrisi.png")
    plt.close()

    # Kaydet
    joblib.dump(stack, os.path.join(model_dir, "yeni_stacking.pkl"))
    joblib.dump(kmeans, os.path.join(model_dir, "yeni_kmeans.pkl"))
    np.save(os.path.join(model_dir, "yeni_esik.npy"), threshold)
    print("\n Yeni modeller 'yeni_' ismiyle kaydedildi.")

if __name__ == "__main__":
    yeni_sistemi_egit()