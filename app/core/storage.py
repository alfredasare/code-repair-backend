from typing import Optional, Dict, Any, List, TypeVar, Generic
from datetime import datetime
from pymongo import MongoClient, IndexModel
from pymongo.collection import Collection
from pymongo.database import Database
from bson import ObjectId
from app.core.config import settings

T = TypeVar('T')


class MongoStorage(Generic[T]):
    def __init__(self, collection_name: str):
        self.client = MongoClient(settings.mongodb_uri)
        self.db: Database = self.client[settings.database_name]
        self.collection: Collection = self.db[collection_name]
        self._setup_indexes()
    
    def _setup_indexes(self):
        pass
    
    def create(self, data: Dict[str, Any]) -> str:
        data["date_created"] = datetime.utcnow()
        data["date_modified"] = datetime.utcnow()
        result = self.collection.insert_one(data)
        return str(result.inserted_id)
    
    def find_one(self, filter_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        result = self.collection.find_one(filter_dict)
        if result:
            result["id"] = str(result["_id"])
            del result["_id"]
        return result
    
    def find_many(self, filter_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = list(self.collection.find(filter_dict))
        for result in results:
            result["id"] = str(result["_id"])
            del result["_id"]
        return results
    
    def update_one(self, filter_dict: Dict[str, Any], update_data: Dict[str, Any]) -> bool:
        update_data["date_modified"] = datetime.utcnow()
        result = self.collection.update_one(filter_dict, {"$set": update_data})
        return result.modified_count > 0
    
    def delete_one(self, filter_dict: Dict[str, Any]) -> bool:
        result = self.collection.delete_one(filter_dict)
        return result.deleted_count > 0
    
    def find_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"_id": ObjectId(id)})
    
    def update_by_id(self, id: str, update_data: Dict[str, Any]) -> bool:
        return self.update_one({"_id": ObjectId(id)}, update_data)
    
    def delete_by_id(self, id: str) -> bool:
        return self.delete_one({"_id": ObjectId(id)})


class UserStorage(MongoStorage):
    def __init__(self):
        super().__init__("users")
    
    def _setup_indexes(self):
        indexes = [
            IndexModel([("email", 1)], unique=True),
            IndexModel([("username", 1)], unique=True),
        ]
        self.collection.create_indexes(indexes)
    
    def find_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"email": email})
    
    def find_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"username": username})


class CriteriaStorage(MongoStorage):
    def __init__(self):
        super().__init__("criteria")
    
    def _setup_indexes(self):
        indexes = [
            IndexModel([("name", 1)], unique=True),
            IndexModel([("date_created", -1)]),
        ]
        self.collection.create_indexes(indexes)
    
    def find_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"name": name})


class PatternStorage(MongoStorage):
    def __init__(self):
        super().__init__("patterns")
    
    def _setup_indexes(self):
        indexes = [
            IndexModel([("pattern_id", 1)], unique=True),
            IndexModel([("name", 1)]),
            IndexModel([("date_created", -1)]),
        ]
        self.collection.create_indexes(indexes)
    
    def find_by_pattern_id(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"pattern_id": pattern_id})
    
    def find_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"name": name})


class ModelStorage(MongoStorage):
    def __init__(self):
        super().__init__("models")
    
    def _setup_indexes(self):
        indexes = [
            IndexModel([("model_id", 1)], unique=True),
            IndexModel([("name", 1)]),
            IndexModel([("type", 1)]),
            IndexModel([("date_created", -1)]),
        ]
        self.collection.create_indexes(indexes)
    
    def find_by_model_id(self, model_id: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"model_id": model_id})
    
    def find_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        return self.find_one({"name": name})
    
    def find_by_type(self, model_type: str) -> List[Dict[str, Any]]:
        return self.find_many({"type": model_type})


class AssessmentStorage(MongoStorage):
    def __init__(self):
        super().__init__("assessments")
    
    def _setup_indexes(self):
        indexes = [
            IndexModel([("user_id", 1)]),
            IndexModel([("cwe_id", 1)]),
            IndexModel([("cve_id", 1)]),
            IndexModel([("pattern_id", 1)]),
            IndexModel([("date_created", -1)]),
        ]
        self.collection.create_indexes(indexes)
    
    def find_by_user_id(self, user_id: str) -> List[Dict[str, Any]]:
        return self.find_many({"user_id": user_id})
    
    def store_results(self, assessment_id: str, scores: Dict[str, Any], 
                     recommendation: Optional[str] = None, vulnerable_code: Optional[str] = None, 
                     model_id: Optional[str] = None) -> bool:
        update_data = {
            "evaluation_scores": scores,
            "date_modified": datetime.utcnow()
        }
        
        if recommendation:
            update_data["repair_recommendation"] = recommendation
        if vulnerable_code:
            update_data["vulnerable_code"] = vulnerable_code
        if model_id:
            update_data["model_id"] = model_id
            
        return self.update_by_id(assessment_id, update_data)


user_storage = UserStorage()
criteria_storage = CriteriaStorage()
pattern_storage = PatternStorage()
model_storage = ModelStorage()
assessment_storage = AssessmentStorage()