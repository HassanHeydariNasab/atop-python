from pymongo import MongoClient
client = MongoClient()
db = client.nishe

from pymongo.collection import ReturnDocument

from bson.objectid import ObjectId


result = db.users.update_many({}, 
    {'$set':
        {
            'remaining_posts': 100, 'remaining_likes': 100
        }
    }
)
print('[DAILY] users daily charging result: matched_count: {}  modified_count: {}'.format(
        result.matched_count, result.modified_count
    )
)
