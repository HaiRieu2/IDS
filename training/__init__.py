"""
ml.training - Module huấn luyện Models
========================================

Chứa:
  - train_ml: huấn luyện Random Forest
  - train_dl: huấn luyện CNN-LSTM
"""

from ml.training.train_ml import train_ml_model
from ml.training.train_dl import train_dl_model, CNNLSTM

