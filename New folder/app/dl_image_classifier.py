"""
Deep Learning Image Classifier for Malware Detection
Uses CNN (TensorFlow/Keras) to detect malicious images and embedded threats.
Provides explainability through Grad-CAM visualization.
"""
import os
import numpy as np
import logging
from pathlib import Path
from typing import Tuple, Dict, Optional, List
import json
import pickle

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    from tensorflow.keras.applications import EfficientNetB0, MobileNetV2
    from tensorflow.keras.preprocessing import image
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

try:
    from PIL import Image
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

from .security_io import validate_and_resolve_path

logger = logging.getLogger(__name__)


class GradCAM:
    """
    Gradient-weighted Class Activation Mapping for explainability.
    Visualizes which parts of an image contributed to the classification.
    """
    
    def __init__(self, model, last_conv_layer_name: str):
        """
        Initialize Grad-CAM.
        
        Args:
            model: Trained Keras model
            last_conv_layer_name: Name of last convolutional layer
        """
        self.model = model
        self.last_conv_layer_name = last_conv_layer_name
        self.grad_model = None
        
        if TF_AVAILABLE:
            self._build_grad_model()
    
    def _build_grad_model(self):
        """Build gradient model for computing CAM."""
        last_conv_layer = self.model.get_layer(self.last_conv_layer_name)
        self.grad_model = models.Model(
            inputs=[self.model.inputs],
            outputs=[last_conv_layer.output, self.model.output]
        )
    
    def compute_heatmap(self, img_array: np.ndarray, pred_index: Optional[int] = None) -> np.ndarray:
        """
        Compute Grad-CAM heatmap.
        
        Args:
            img_array: Preprocessed image array
            pred_index: Target class index (None for predicted class)
        
        Returns:
            Heatmap array
        """
        if not TF_AVAILABLE or self.grad_model is None:
            return np.zeros((224, 224))
        
        with tf.GradientTape() as tape:
            conv_outputs, predictions = self.grad_model(img_array)
            if pred_index is None:
                pred_index = tf.argmax(predictions[0])
            class_channel = predictions[:, pred_index]
        
        # Compute gradients
        grads = tape.gradient(class_channel, conv_outputs)
        
        # Pool gradients
        pooled_grads = tf.reduce_mean(grads, axis=(0, 1, 2))
        
        # Weight feature maps
        conv_outputs = conv_outputs[0]
        heatmap = conv_outputs @ pooled_grads[..., tf.newaxis]
        heatmap = tf.squeeze(heatmap)
        
        # Normalize
        heatmap = tf.maximum(heatmap, 0) / tf.math.reduce_max(heatmap)
        return heatmap.numpy()
    
    def overlay_heatmap(self, heatmap: np.ndarray, original_img: np.ndarray, 
                       alpha: float = 0.4) -> np.ndarray:
        """
        Overlay heatmap on original image.
        
        Args:
            heatmap: Grad-CAM heatmap
            original_img: Original image array
            alpha: Transparency of heatmap
        
        Returns:
            Overlayed image
        """
        if not CV2_AVAILABLE:
            return original_img
        
        # Resize heatmap to match image
        heatmap = cv2.resize(heatmap, (original_img.shape[1], original_img.shape[0]))
        heatmap = np.uint8(255 * heatmap)
        heatmap = cv2.applyColorMap(heatmap, cv2.COLORMAP_JET)
        
        # Overlay
        superimposed = cv2.addWeighted(original_img, 1 - alpha, heatmap, alpha, 0)
        return superimposed


class ImageMalwareClassifier:
    """
    Deep learning classifier for detecting malicious images.
    Supports training, prediction, and explainability.
    """
    
    def __init__(self, model_path: Optional[str] = None, 
                 architecture: str = 'efficientnet'):
        """
        Initialize image classifier.
        
        Args:
            model_path: Path to saved model (None for new model)
            architecture: Model architecture ('efficientnet', 'mobilenet', 'custom')
        """
        self.model = None
        self.architecture = architecture
        self.model_path = model_path
        self.input_shape = (224, 224, 3)
        self.class_names = ['benign', 'malicious']
        self.grad_cam = None
        
        if not TF_AVAILABLE:
            logger.warning("TensorFlow not available. Install with: pip install tensorflow")
            return
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self.model = self._build_model()
    
    def _build_model(self) -> Optional[keras.Model]:
        """
        Build CNN model architecture.
        
        Returns:
            Keras model
        """
        if not TF_AVAILABLE:
            return None
        
        if self.architecture == 'efficientnet':
            base_model = EfficientNetB0(
                include_top=False,
                weights='imagenet',
                input_shape=self.input_shape
            )
            last_conv_layer = 'top_activation'
            
        elif self.architecture == 'mobilenet':
            base_model = MobileNetV2(
                include_top=False,
                weights='imagenet',
                input_shape=self.input_shape
            )
            last_conv_layer = 'out_relu'
            
        else:  # Custom architecture
            base_model = models.Sequential([
                layers.Conv2D(32, (3, 3), activation='relu', 
                            input_shape=self.input_shape),
                layers.MaxPooling2D((2, 2)),
                layers.Conv2D(64, (3, 3), activation='relu'),
                layers.MaxPooling2D((2, 2)),
                layers.Conv2D(128, (3, 3), activation='relu', name='last_conv'),
                layers.MaxPooling2D((2, 2)),
            ])
            last_conv_layer = 'last_conv'
        
        # Add classification head
        model = models.Sequential([
            base_model,
            layers.GlobalAveragePooling2D(),
            layers.Dropout(0.3),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(len(self.class_names), activation='softmax')
        ])
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy', 
                    keras.metrics.Precision(name='precision'),
                    keras.metrics.Recall(name='recall')]
        )
        
        # Initialize Grad-CAM
        self.grad_cam = GradCAM(model, last_conv_layer)
        
        logger.info(f"Built {self.architecture} model with {model.count_params():,} parameters")
        return model
    
    def preprocess_image(self, img_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Preprocess image for model input.
        
        Args:
            img_path: Path to image file
        
        Returns:
            Tuple of (preprocessed_array, original_array)
        """
        try:
            path = validate_and_resolve_path(img_path, must_exist=True)
            
            # Load and resize image
            img = image.load_img(str(path), target_size=self.input_shape[:2])
            img_array = image.img_to_array(img)
            original_array = img_array.copy()
            
            # Normalize
            img_array = np.expand_dims(img_array, axis=0)
            img_array = keras.applications.efficientnet.preprocess_input(img_array)
            
            return img_array, original_array
        
        except Exception as e:
            logger.error(f"Image preprocessing failed for {img_path}: {e}")
            raise
    
    def predict(self, img_path: str, explain: bool = True) -> Dict:
        """
        Predict if image is malicious.
        
        Args:
            img_path: Path to image file
            explain: Whether to generate explainability heatmap
        
        Returns:
            Dictionary with prediction results and explanation
        """
        if not TF_AVAILABLE or self.model is None:
            return {
                'error': 'Model not available',
                'is_malicious': False,
                'confidence': 0.0
            }
        
        try:
            # Preprocess
            img_array, original_array = self.preprocess_image(img_path)
            
            # Predict
            predictions = self.model.predict(img_array, verbose=0)
            pred_class = np.argmax(predictions[0])
            confidence = float(predictions[0][pred_class])
            
            result = {
                'is_malicious': self.class_names[pred_class] == 'malicious',
                'confidence': confidence,
                'class': self.class_names[pred_class],
                'probabilities': {
                    name: float(prob) 
                    for name, prob in zip(self.class_names, predictions[0])
                },
                'model_architecture': self.architecture
            }
            
            # Generate explanation
            if explain and self.grad_cam is not None:
                heatmap = self.grad_cam.compute_heatmap(img_array, pred_class)
                result['explanation'] = {
                    'method': 'Grad-CAM',
                    'heatmap_shape': heatmap.shape,
                    'suspicious_regions': self._analyze_heatmap(heatmap)
                }
            
            return result
        
        except Exception as e:
            logger.error(f"Prediction failed for {img_path}: {e}")
            return {
                'error': str(e),
                'is_malicious': False,
                'confidence': 0.0
            }
    
    def _analyze_heatmap(self, heatmap: np.ndarray) -> Dict:
        """
        Analyze Grad-CAM heatmap to identify suspicious regions.
        
        Args:
            heatmap: Grad-CAM heatmap
        
        Returns:
            Dictionary describing suspicious regions
        """
        # Find high-activation regions
        threshold = np.percentile(heatmap, 90)
        high_regions = np.where(heatmap > threshold)
        
        if len(high_regions[0]) == 0:
            return {'num_regions': 0, 'description': 'No significant regions'}
        
        # Calculate region statistics
        center_y = np.mean(high_regions[0]) / heatmap.shape[0]
        center_x = np.mean(high_regions[1]) / heatmap.shape[1]
        coverage = len(high_regions[0]) / (heatmap.shape[0] * heatmap.shape[1])
        
        return {
            'num_regions': len(high_regions[0]),
            'center': [float(center_x), float(center_y)],
            'coverage_percent': float(coverage * 100),
            'description': f'Suspicious features detected in {coverage*100:.1f}% of image'
        }
    
    def train(self, train_dir: str, val_dir: Optional[str] = None,
              epochs: int = 10, batch_size: int = 32,
              save_path: Optional[str] = None) -> Dict:
        """
        Train the model on labeled data.
        
        Args:
            train_dir: Directory with training data (benign/, malicious/)
            val_dir: Directory with validation data
            epochs: Number of training epochs
            batch_size: Batch size
            save_path: Path to save trained model
        
        Returns:
            Training history
        """
        if not TF_AVAILABLE or self.model is None:
            return {'error': 'Model not available'}
        
        try:
            # Data augmentation
            train_datagen = keras.preprocessing.image.ImageDataGenerator(
                preprocessing_function=keras.applications.efficientnet.preprocess_input,
                rotation_range=20,
                width_shift_range=0.2,
                height_shift_range=0.2,
                horizontal_flip=True,
                zoom_range=0.2
            )
            
            val_datagen = keras.preprocessing.image.ImageDataGenerator(
                preprocessing_function=keras.applications.efficientnet.preprocess_input
            )
            
            # Load datasets
            train_generator = train_datagen.flow_from_directory(
                train_dir,
                target_size=self.input_shape[:2],
                batch_size=batch_size,
                class_mode='sparse',
                classes=self.class_names
            )
            
            validation_generator = None
            if val_dir:
                validation_generator = val_datagen.flow_from_directory(
                    val_dir,
                    target_size=self.input_shape[:2],
                    batch_size=batch_size,
                    class_mode='sparse',
                    classes=self.class_names
                )
            
            # Callbacks
            callbacks = [
                keras.callbacks.EarlyStopping(
                    monitor='val_loss' if val_dir else 'loss',
                    patience=5,
                    restore_best_weights=True
                ),
                keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss' if val_dir else 'loss',
                    factor=0.5,
                    patience=3
                )
            ]
            
            # Train
            history = self.model.fit(
                train_generator,
                epochs=epochs,
                validation_data=validation_generator,
                callbacks=callbacks,
                verbose=1
            )
            
            # Save model
            if save_path:
                self.save_model(save_path)
            
            return {
                'epochs_trained': len(history.history['loss']),
                'final_accuracy': float(history.history['accuracy'][-1]),
                'final_loss': float(history.history['loss'][-1]),
                'history': {k: [float(v) for v in vals] 
                           for k, vals in history.history.items()}
            }
        
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return {'error': str(e)}
    
    def save_model(self, path: str):
        """Save model to disk."""
        if self.model is not None:
            self.model.save(path)
            logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str):
        """Load model from disk."""
        if not TF_AVAILABLE:
            return
        
        try:
            self.model = keras.models.load_model(path)
            logger.info(f"Model loaded from {path}")
            
            # Reinitialize Grad-CAM
            last_conv_layers = {
                'efficientnet': 'top_activation',
                'mobilenet': 'out_relu',
                'custom': 'last_conv'
            }
            layer_name = last_conv_layers.get(self.architecture, 'last_conv')
            self.grad_cam = GradCAM(self.model, layer_name)
            
        except Exception as e:
            logger.error(f"Failed to load model from {path}: {e}")
    
    def get_model_info(self) -> Dict:
        """Get model information and statistics."""
        if self.model is None:
            return {'available': False}
        
        return {
            'available': True,
            'architecture': self.architecture,
            'input_shape': self.input_shape,
            'num_classes': len(self.class_names),
            'class_names': self.class_names,
            'total_params': self.model.count_params() if TF_AVAILABLE else 0,
            'grad_cam_enabled': self.grad_cam is not None
        }
