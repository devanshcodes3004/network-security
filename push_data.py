import os
import sys
import json

from dotenv import load_dotenv
load_dotenv()

# Load MongoDB URL safely
MONGO_DB_URL = os.getenv("MONGO_DB_URL")

import certifi
ca = certifi.where()

import pandas as pd
import pymongo

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging


class NetworkDataExtract():

    def __init__(self):
        try:
            if MONGO_DB_URL is None:
                raise Exception("MongoDB connection string not found in .env file")
            logging.info("MongoDB URL loaded successfully")
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    # Step 1: Extract + Transform (CSV → JSON)
    def csv_to_json_convertor(self, file_path):
        try:
            logging.info("Reading CSV file")

            data = pd.read_csv(file_path)
            data.reset_index(drop=True, inplace=True)

            logging.info("Converting CSV to JSON format")

            records = list(json.loads(data.T.to_json()).values())

            logging.info("CSV successfully converted into JSON records")

            return records

        except Exception as e:
            raise NetworkSecurityException(e, sys)

    # Step 2: Load (Insert into MongoDB Atlas)
    def insert_data_mongodb(self, records, database, collection):
        try:
            logging.info("Connecting to MongoDB Atlas")

            mongo_client = pymongo.MongoClient(
                MONGO_DB_URL,
                tls=True,
                tlsCAFile=ca
            )

            logging.info("MongoDB connection successful")

            db = mongo_client[database]
            collection_obj = db[collection]

            logging.info("Inserting records into MongoDB")

            collection_obj.insert_many(records)

            logging.info("Data inserted successfully")

            return len(records)

        except Exception as e:
            raise NetworkSecurityException(e, sys)


# Main Execution Block
if __name__ == "__main__":

    try:
        FILE_PATH = r"Network_Data\phisingData.csv"

        DATABASE = "Devansh"
        COLLECTION = "NetworkData"

        network_obj = NetworkDataExtract()

        records = network_obj.csv_to_json_convertor(FILE_PATH)

        print(f"Total records converted: {len(records)}")

        inserted_records = network_obj.insert_data_mongodb(
            records,
            DATABASE,
            COLLECTION
        )

        print(f"Total records inserted into MongoDB: {inserted_records}")

    except Exception as e:
        raise NetworkSecurityException(e, sys)