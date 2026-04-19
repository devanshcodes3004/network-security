from networksecurity.entity.artifact_entity import (
    DataIngestionArtifact,
    DataValidationArtifact,
    DataTransformationArtifact
)

from networksecurity.entity.config_entity import (
    DataValidationConfig,
    TrainingPipelineConfig,
    DataIngestionConfig,
    DataTransformationConfig
)

from networksecurity.components.data_ingestion import DataIngestion
from networksecurity.components.data_validation import DataValidation
from networksecurity.components.data_transformation import DataTransformation

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.constants.training_pipeline import SCHEMA_FILE_PATH

from networksecurity.components.model_trainer import ModelTrainer
from networksecurity.entity.config_entity import ModelTrainerConfig

from scipy.stats import ks_2samp

import pandas as pd
import os
import sys

from networksecurity.utils.main_utils.utils import (
    read_yaml_file,
    write_yaml_file
)


if __name__ == "__main__":
    try:
        # Training Pipeline Config
        training_pipeline_config = TrainingPipelineConfig()

        # Data Ingestion
        data_ingestion_config = DataIngestionConfig(training_pipeline_config)
        data_ingestion = DataIngestion(data_ingestion_config)

        logging.info("Initiated the data ingestion")
        data_ingestion_artifact = data_ingestion.initiate_data_ingestion()
        logging.info("Data ingestion completed")

        print(data_ingestion_artifact)

        # Data Validation
        data_validation_config = DataValidationConfig(training_pipeline_config)
        data_validation = DataValidation(
            data_ingestion_artifact,
            data_validation_config
        )

        logging.info("Initiated the data validation")
        data_validation_artifact = data_validation.initiate_data_validation()
        logging.info("Data validation completed")

        print(data_validation_artifact)

        # Data Transformation
        data_transformation_config = DataTransformationConfig(
            training_pipeline_config
        )

        logging.info("Data transformation started")

        data_transformation = DataTransformation(
            data_validation_artifact,
            data_transformation_config
        )

        data_transformation_artifact = (
            data_transformation.initiate_data_transformation()
        )

        print(data_transformation_artifact)

        logging.info("Data transformation completed")


        logging.info("Model training started")
        model_trainer_config = ModelTrainerConfig(training_pipeline_config)
        model_trainer = ModelTrainer(model_trainer_config, data_transformation_artifact)    
        model_trainer_artifact = model_trainer.initiate_model_trainer()

        logging.info("Model training completed")

    except Exception as e:
        raise NetworkSecurityException(e, sys)