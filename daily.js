const MongoClient = require('mongodb').MongoClient
const MONGODB_URL = 'mongodb://127.0.0.1:27017';
const ObjectID = require('mongodb').ObjectID

var db
MongoClient.connect(MONGODB_URL, {
    useNewUrlParser: true
    }, (err, client) => {
    if (err) return console.error('[DAILY] ERROR mongodb: '+err)
    db = client.db('atop')
    db.collection('users').updateMany({}, {$set: {remaining_likes: 100}}, (err, r) => {
        if (err)
            console.error('[DAILY] ERROR mongodb: '+err)
        console.log('[DAILY] LOG mongodb: '+r)
        client.close()
        return;
    })
})