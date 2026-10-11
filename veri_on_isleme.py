#2. kısım
import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

class VeriOnIsleyici:
    def __init__(self):
        self.scaler = MinMaxScaler()
        self.cat_cols = ['protocol_type', 'service', 'flag']
        self.encoders = {}
        self.train_columns = None 

    def _temizle(self, df):
        cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
        df = df[cols].copy()
        # Sayısal boşlukları 0 ile doldur (İmputation)
        df.fillna(0, inplace=True)
        df['src_bytes'] = np.log1p(df['src_bytes'].astype(float))
        df['dst_bytes'] = np.log1p(df['dst_bytes'].astype(float))
        return df

    def fit_transform(self, df):
        df = self._temizle(df)
        for col in self.cat_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            self.encoders[col] = le
        
        df = pd.get_dummies(df, columns=self.cat_cols)
        self.train_columns = df.columns.tolist() # Eğitim sütunlarını kaydet
        
        df[self.train_columns] = self.scaler.fit_transform(df[self.train_columns])
        return df

    def transform(self, df):
        df = self._temizle(df)
        for col in self.cat_cols:
            le = self.encoders[col]
            df[col] = df[col].astype(str).map(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )
        
        df = pd.get_dummies(df, columns=self.cat_cols)

        # Eksik sütunlar 0 (yok) 
        for col in self.train_columns:
            if col not in df.columns:
                df[col] = 0
        
        df = df[self.train_columns] # Sütun sırasını eşitle
        df[self.train_columns] = self.scaler.transform(df[self.train_columns])
        return df

def yeni_veriyi_hazirla(csv_yolu, veri_tipi="egitim"):
    kolonlar = [
        'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
        'wrong_fragment','urgent','hot','num_failed_logins','logged_in',
        'num_compromised','root_shell','su_attempted','num_root',
        'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
        'is_host_login','is_guest_login','count','srv_count','serror_rate',
        'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
        'diff_srv_rate','srv_diff_host_rate','dst_host_count',
        'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
        'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
        'dst_host_srv_rerror_rate','label','difficulty'
    ]

    df = pd.read_csv(csv_yolu, header=None)
    df.columns = kolonlar
    y = (df['label'] != 'normal').astype(int)
    
   
    if veri_tipi == "egitim":
        isleyici = VeriOnIsleyici()
        X = isleyici.fit_transform(df)
        joblib.dump(isleyici, "modeller/yeni_isleyici.pkl")
    else:
        isleyici = joblib.load("modeller/yeni_isleyici.pkl")
        X = isleyici.transform(df)

    joblib.dump((X, y), f"modeller/yeni_{veri_tipi}_verisi.pkl")
    print(f" {veri_tipi} verisi hazırlandı.")

if __name__ == "__main__":
    yeni_veriyi_hazirla("veriSetleri/KDDTrain+.txt", "egitim")
    yeni_veriyi_hazirla("veriSetleri/KDDTest+.txt", "test")