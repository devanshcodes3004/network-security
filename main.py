from networksecurity.entity.artifact_entity import (
    DataIngestionArtifact,
    DataValidationArtifact
)

from networksecurity.entity.config_entity import (
    DataValidationConfig,
    TrainingPipelineConfig,
    DataIngestionConfig
)

from networksecurity.components.data_ingestion import DataIngestion
from networksecurity.components.data_validation import DataValidation

from networksecurity.exception.exception import NetworkSecurityException

from networksecurity.logging.logger import logging

from networksecurity.constants.training_pipeline import SCHEMA_FILE_PATH

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
        # Training pipeline configuration
        training_pipeline_config = TrainingPipelineConfig()

        # Data ingestion configuration
        data_ingestion_config = DataIngestionConfig(training_pipeline_config)

        # Data ingestion object
        data_ingestion = DataIngestion(data_ingestion_config)

        logging.info("Initiate the data ingestion")

        # Start data ingestion
        data_ingestion_artifact = data_ingestion.initiate_data_ingestion()

        logging.info("Data ingestion completed")

        # Data validation configuration
        data_validation_config = DataValidationConfig(training_pipeline_config)

        # Data validation object
        data_validation = DataValidation(
            data_ingestion_artifact,
            data_validation_config
        )

        logging.info("Initiate the data validation")

        # Start data validation
        data_validation_artifact = data_validation.initiate_data_validation()

        print(data_validation_artifact)

    except Exception as e:
        raise NetworkSecurityException(e, sys)