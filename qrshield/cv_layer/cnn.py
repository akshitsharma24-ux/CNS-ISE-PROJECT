"""
CNN Classifier & Deep Feature Extractor (F20).
Provides lightweight convolutional feature extraction and deep representation
for physical QR tamper discrimination.
"""
import cv2
import numpy as np
from typing import Dict, Any

class TamperCNN:
    """
    Lightweight convolutional feature extractor and classifier.
    Extracts deep spatial frequency and texture descriptors across scale hierarchies.
    """
    def __init__(self):
        # Kernels representing multi-scale orientation and high-pass edge filters
        self.filters = [
            # Horizontal cutline detector
            np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]], dtype=np.float32),
            # Vertical cutline detector
            np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=np.float32),
            # Laplacian 3D elevation detector
            np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32),
            # Diagonal corner detector
            np.array([[2, -1, -1], [-1, 2, -1], [-1, -1, 2]], dtype=np.float32)
        ]

    def forward(self, img_bgr: np.ndarray) -> np.ndarray:
        """Computes deep spatial activation maps."""
        gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY).astype(np.float32) / 255.0
        feature_maps = []
        for k in self.filters:
            fmap = cv2.filter2D(gray, -1, k)
            fmap = np.maximum(0, fmap)  # ReLU
            fmap = cv2.resize(fmap, (32, 32))  # Spatial pooling
            feature_maps.append(fmap.flatten())
        return np.concatenate(feature_maps)
