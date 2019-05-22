# use cron to run this command daily:
# cd /home/USER/atop-server && /usr/local/bin/pipenv run python3 /home/USER/atop-server/daily.py 2>&1 | logger -t

from pymongo import MongoClient
client = MongoClient()
db = client.atop

from pymongo.collection import ReturnDocument

from bson.objectid import ObjectId


result = db.users.update_many({}, 
    {'$set':
        {
            'remaining_likes': 100
        }
    }
)
print('[result] users daily charging: matched_count: {}  modified_count: {}'.format(
        result.matched_count, result.modified_count
    )
)
