var searchIndex = JSON.parse('{\
"m_captcha":{"doc":"mCaptcha is a proof of work based Denaial-of-Service …","i":[[0,"defense","m_captcha","Defense datatypes",null,null],[3,"Level","m_captcha::defense","Level struct that describes threshold-difficulty factor …",null,null],[3,"LevelBuilder","","Bulder struct for [Level] to describe …",null,null],[11,"visitor_threshold","","set visitor count for level",0,[[]]],[11,"difficulty_factor","","set difficulty factor for level. difficulty_factor can\'t …",0,[[],["captcharesult",6]]],[11,"build","","build Level struct",0,[[],[["captcharesult",6],["level",3]]]],[3,"Defense","","struct describes all the different [Level]s at which an …",null,null],[3,"DefenseBuilder","","Builder struct for [Defense]",null,null],[11,"add_level","","add a level to [Defense]",1,[[["level",3]],["captcharesult",6]]],[11,"build","","Build [Defense]",1,[[],[["defense",3],["captcharesult",6]]]],[11,"get_difficulty","","! Difficulty is calculated as: ! …",2,[[]]],[11,"tighten_up","","tighten up defense. Increases defense level by a factor …",2,[[]]],[11,"loosen_up","","Loosen up defense. Decreases defense level by a factor of …",2,[[]]],[11,"max_defense","","Set defense to maximum level",2,[[]]],[11,"min_defense","","Set defense to minimum level",2,[[]]],[11,"visitor_threshold","","Get current level\'s  visitor threshold",2,[[]]],[0,"errors","m_captcha","Errors and Result module",null,null],[4,"CaptchaError","m_captcha::errors","Error datatype",null,null],[13,"LevelEmpty","","When configuring m_captcha, [DefenseBuilder][…",3,null],[13,"DifficultyFactorZero","","Visitor count must be a whole number(zero and above). …",3,null],[13,"SetDifficultyFactor","","Difficulty factor must be set",3,null],[13,"SetVisitorThreshold","","Visitor threshold must be set",3,null],[13,"DuplicateVisitorCount","","Visitor count must be Unique",3,null],[13,"DecreaseingDifficultyFactor","","Difficulty factor should increase with level",3,null],[13,"MailboxError","","Difficulty factor should increase with level",3,null],[13,"InsuffiencientDifficulty","","Happens when submitted work doesn\'t satisfy the required …",3,null],[13,"StringNotFound","","Happens when submitted work is computed over string that …",3,null],[6,"CaptchaResult","","[Result] datatype for m_captcha",null,null],[0,"master","m_captcha","[Master] actor module that manages [MCaptcha] actors",null,null],[3,"Master","m_captcha::master","This Actor manages the [MCaptcha] actors. A service can …",null,null],[11,"add_site","","add [MCaptcha] actor to [Master]",4,[[["addsite",3]]]],[11,"new","","create new master",4,[[]]],[11,"get_site","","get [MCaptcha] actor from [Master]",4,[[],[["addr",3],["option",4]]]],[3,"GetSite","","Message to get an [MCaptcha] actor from master",null,null],[12,"0","","",5,null],[3,"AddSite","","Message to add an [MCaptcha] actor to [Master]",null,null],[12,"id","","",6,null],[12,"addr","","",6,null],[3,"AddSiteBuilder","","Builder for <code>AddSite</code>.",null,null],[11,"id","","",7,[[["string",3]]]],[11,"addr","","",7,[[["addr",3],["mcaptcha",3]]]],[11,"build","","Builds a new <code>AddSite</code>.",7,[[],[["result",4],["string",3],["addsite",3]]]],[0,"mcaptcha","m_captcha","MCaptcha actor module that manages defense levels",null,null],[3,"MCaptcha","m_captcha::mcaptcha","This struct represents the mCaptcha state and is used to …",null,null],[3,"MCaptchaBuilder","","Builder for <code>MCaptcha</code>.",null,null],[11,"defense","","",8,[[["defense",3]]]],[11,"duration","","",8,[[]]],[11,"build","","Builds a new <code>MCaptcha</code>.",8,[[],[["string",3],["result",4],["mcaptcha",3]]]],[11,"add_visitor","","increments the visitor count by one",9,[[]]],[11,"decrement_visitor","","decrements the visitor count by one",9,[[]]],[11,"get_difficulty","","get current difficulty factor",9,[[]]],[11,"get_duration","","get [MCaptcha]\'s lifetime",9,[[]]],[3,"Visitor","","Message to increment the visitor count returns difficulty …",null,null],[3,"VisitorResult","","Struct representing the return datatime of [Visitor] …",null,null],[12,"duration","","",10,null],[12,"difficulty_factor","","",10,null],[0,"cache","m_captcha","message datatypes to interact with [MCaptcha] actor Cache …",null,null],[0,"hashcache","m_captcha::cache","In-memory cache implementation that uses [HashMap]",null,null],[3,"HashCache","m_captcha::cache::hashcache","cache datastructure implementing [Save]",null,null],[0,"messages","m_captcha::cache","Messages that can be sent to cache data structures …",null,null],[3,"Cache","m_captcha::cache::messages","Message to cache PoW difficulty factor and string",null,null],[12,"string","","",11,null],[12,"difficulty_factor","","",11,null],[12,"duration","","",11,null],[3,"CacheBuilder","","Builder for <code>Cache</code>.",null,null],[11,"string","","",12,[[["string",3]]]],[11,"difficulty_factor","","",12,[[]]],[11,"duration","","",12,[[]]],[11,"build","","Builds a new <code>Cache</code>.",12,[[],[["result",4],["cache",3],["string",3]]]],[11,"new","","",11,[[["powconfig",3],["visitorresult",3]]]],[3,"Retrive","","Message to retrive the the difficulty factor for the …",null,null],[12,"0","","",13,null],[3,"DeleteString","","Message to delete cached PoW difficulty factor and string …",null,null],[12,"0","","",14,null],[8,"Save","m_captcha::cache","Describes actor handler trait impls that are required by …",null,null],[0,"pow","m_captcha","PoW datatypes used in client-server interaction",null,null],[3,"ConfigBuilder","m_captcha::pow","Builder for <code>Config</code>.",null,null],[3,"PoWConfig","","PoW requirement datatype that is be sent to clients for …",null,null],[12,"string","","",15,null],[12,"difficulty_factor","","",15,null],[11,"new","","create new instance of [PoWConfig]",15,[[]]],[3,"Work","","PoW datatype that clients send to server",null,null],[12,"string","","",16,null],[12,"result","","",16,null],[12,"nonce","","",16,null],[0,"system","m_captcha","module describing mCaptcha system",null,null],[3,"System","m_captcha::system","struct describing various bits of data required for an …",null,null],[12,"master","","",17,null],[3,"SystemBuilder","","Builder for <code>System</code>.",null,null],[11,"master","","",18,[[["addr",3],["master",3]]]],[11,"cache","","",18,[[["addr",3]]]],[11,"pow","","",18,[[["config",3]]]],[11,"build","","Builds a new <code>System</code>.",18,[[],[["system",3],["string",3],["result",4]]]],[11,"get_pow","","utility function to get difficulty factor of site <code>id</code> and …",17,[[["string",3]]]],[11,"verify_pow","","utility function to verify [Work]",17,[[["work",3]]]],[11,"from","m_captcha::defense","",19,[[]]],[11,"into","","",19,[[]]],[11,"to_owned","","",19,[[]]],[11,"clone_into","","",19,[[]]],[11,"borrow","","",19,[[]]],[11,"borrow_mut","","",19,[[]]],[11,"try_from","","",19,[[],["result",4]]],[11,"try_into","","",19,[[],["result",4]]],[11,"type_id","","",19,[[],["typeid",3]]],[11,"vzip","","",19,[[]]],[11,"from","","",0,[[]]],[11,"into","","",0,[[]]],[11,"to_owned","","",0,[[]]],[11,"clone_into","","",0,[[]]],[11,"borrow","","",0,[[]]],[11,"borrow_mut","","",0,[[]]],[11,"try_from","","",0,[[],["result",4]]],[11,"try_into","","",0,[[],["result",4]]],[11,"type_id","","",0,[[],["typeid",3]]],[11,"vzip","","",0,[[]]],[11,"from","","",2,[[]]],[11,"into","","",2,[[]]],[11,"to_owned","","",2,[[]]],[11,"clone_into","","",2,[[]]],[11,"borrow","","",2,[[]]],[11,"borrow_mut","","",2,[[]]],[11,"try_from","","",2,[[],["result",4]]],[11,"try_into","","",2,[[],["result",4]]],[11,"type_id","","",2,[[],["typeid",3]]],[11,"vzip","","",2,[[]]],[11,"from","","",1,[[]]],[11,"into","","",1,[[]]],[11,"to_owned","","",1,[[]]],[11,"clone_into","","",1,[[]]],[11,"borrow","","",1,[[]]],[11,"borrow_mut","","",1,[[]]],[11,"try_from","","",1,[[],["result",4]]],[11,"try_into","","",1,[[],["result",4]]],[11,"type_id","","",1,[[],["typeid",3]]],[11,"vzip","","",1,[[]]],[11,"from","m_captcha::errors","",3,[[]]],[11,"into","","",3,[[]]],[11,"to_owned","","",3,[[]]],[11,"clone_into","","",3,[[]]],[11,"to_string","","",3,[[],["string",3]]],[11,"borrow","","",3,[[]]],[11,"borrow_mut","","",3,[[]]],[11,"try_from","","",3,[[],["result",4]]],[11,"try_into","","",3,[[],["result",4]]],[11,"type_id","","",3,[[],["typeid",3]]],[11,"vzip","","",3,[[]]],[11,"from","m_captcha::master","",4,[[]]],[11,"into","","",4,[[]]],[11,"to_owned","","",4,[[]]],[11,"clone_into","","",4,[[]]],[11,"borrow","","",4,[[]]],[11,"borrow_mut","","",4,[[]]],[11,"try_from","","",4,[[],["result",4]]],[11,"try_into","","",4,[[],["result",4]]],[11,"type_id","","",4,[[],["typeid",3]]],[11,"vzip","","",4,[[]]],[11,"from","","",5,[[]]],[11,"into","","",5,[[]]],[11,"borrow","","",5,[[]]],[11,"borrow_mut","","",5,[[]]],[11,"try_from","","",5,[[],["result",4]]],[11,"try_into","","",5,[[],["result",4]]],[11,"type_id","","",5,[[],["typeid",3]]],[11,"vzip","","",5,[[]]],[11,"from","","",6,[[]]],[11,"into","","",6,[[]]],[11,"borrow","","",6,[[]]],[11,"borrow_mut","","",6,[[]]],[11,"try_from","","",6,[[],["result",4]]],[11,"try_into","","",6,[[],["result",4]]],[11,"type_id","","",6,[[],["typeid",3]]],[11,"vzip","","",6,[[]]],[11,"from","","",7,[[]]],[11,"into","","",7,[[]]],[11,"to_owned","","",7,[[]]],[11,"clone_into","","",7,[[]]],[11,"borrow","","",7,[[]]],[11,"borrow_mut","","",7,[[]]],[11,"try_from","","",7,[[],["result",4]]],[11,"try_into","","",7,[[],["result",4]]],[11,"type_id","","",7,[[],["typeid",3]]],[11,"vzip","","",7,[[]]],[11,"from","m_captcha::mcaptcha","",9,[[]]],[11,"into","","",9,[[]]],[11,"to_owned","","",9,[[]]],[11,"clone_into","","",9,[[]]],[11,"borrow","","",9,[[]]],[11,"borrow_mut","","",9,[[]]],[11,"try_from","","",9,[[],["result",4]]],[11,"try_into","","",9,[[],["result",4]]],[11,"type_id","","",9,[[],["typeid",3]]],[11,"vzip","","",9,[[]]],[11,"from","","",8,[[]]],[11,"into","","",8,[[]]],[11,"to_owned","","",8,[[]]],[11,"clone_into","","",8,[[]]],[11,"borrow","","",8,[[]]],[11,"borrow_mut","","",8,[[]]],[11,"try_from","","",8,[[],["result",4]]],[11,"try_into","","",8,[[],["result",4]]],[11,"type_id","","",8,[[],["typeid",3]]],[11,"vzip","","",8,[[]]],[11,"from","","",20,[[]]],[11,"into","","",20,[[]]],[11,"borrow","","",20,[[]]],[11,"borrow_mut","","",20,[[]]],[11,"try_from","","",20,[[],["result",4]]],[11,"try_into","","",20,[[],["result",4]]],[11,"type_id","","",20,[[],["typeid",3]]],[11,"vzip","","",20,[[]]],[11,"from","","",10,[[]]],[11,"into","","",10,[[]]],[11,"borrow","","",10,[[]]],[11,"borrow_mut","","",10,[[]]],[11,"try_from","","",10,[[],["result",4]]],[11,"try_into","","",10,[[],["result",4]]],[11,"type_id","","",10,[[],["typeid",3]]],[11,"vzip","","",10,[[]]],[11,"from","m_captcha::cache::hashcache","",21,[[]]],[11,"into","","",21,[[]]],[11,"to_owned","","",21,[[]]],[11,"clone_into","","",21,[[]]],[11,"borrow","","",21,[[]]],[11,"borrow_mut","","",21,[[]]],[11,"try_from","","",21,[[],["result",4]]],[11,"try_into","","",21,[[],["result",4]]],[11,"type_id","","",21,[[],["typeid",3]]],[11,"vzip","","",21,[[]]],[11,"from","m_captcha::cache::messages","",11,[[]]],[11,"into","","",11,[[]]],[11,"borrow","","",11,[[]]],[11,"borrow_mut","","",11,[[]]],[11,"try_from","","",11,[[],["result",4]]],[11,"try_into","","",11,[[],["result",4]]],[11,"type_id","","",11,[[],["typeid",3]]],[11,"vzip","","",11,[[]]],[11,"from","","",12,[[]]],[11,"into","","",12,[[]]],[11,"to_owned","","",12,[[]]],[11,"clone_into","","",12,[[]]],[11,"borrow","","",12,[[]]],[11,"borrow_mut","","",12,[[]]],[11,"try_from","","",12,[[],["result",4]]],[11,"try_into","","",12,[[],["result",4]]],[11,"type_id","","",12,[[],["typeid",3]]],[11,"vzip","","",12,[[]]],[11,"from","","",13,[[]]],[11,"into","","",13,[[]]],[11,"borrow","","",13,[[]]],[11,"borrow_mut","","",13,[[]]],[11,"try_from","","",13,[[],["result",4]]],[11,"try_into","","",13,[[],["result",4]]],[11,"type_id","","",13,[[],["typeid",3]]],[11,"vzip","","",13,[[]]],[11,"from","","",14,[[]]],[11,"into","","",14,[[]]],[11,"borrow","","",14,[[]]],[11,"borrow_mut","","",14,[[]]],[11,"try_from","","",14,[[],["result",4]]],[11,"try_into","","",14,[[],["result",4]]],[11,"type_id","","",14,[[],["typeid",3]]],[11,"vzip","","",14,[[]]],[11,"from","m_captcha::pow","",22,[[]]],[11,"into","","",22,[[]]],[11,"to_owned","","",22,[[]]],[11,"clone_into","","",22,[[]]],[11,"borrow","","",22,[[]]],[11,"borrow_mut","","",22,[[]]],[11,"try_from","","",22,[[],["result",4]]],[11,"try_into","","",22,[[],["result",4]]],[11,"type_id","","",22,[[],["typeid",3]]],[11,"vzip","","",22,[[]]],[11,"from","","",15,[[]]],[11,"into","","",15,[[]]],[11,"to_owned","","",15,[[]]],[11,"clone_into","","",15,[[]]],[11,"borrow","","",15,[[]]],[11,"borrow_mut","","",15,[[]]],[11,"try_from","","",15,[[],["result",4]]],[11,"try_into","","",15,[[],["result",4]]],[11,"type_id","","",15,[[],["typeid",3]]],[11,"vzip","","",15,[[]]],[11,"from","","",16,[[]]],[11,"into","","",16,[[]]],[11,"to_owned","","",16,[[]]],[11,"clone_into","","",16,[[]]],[11,"borrow","","",16,[[]]],[11,"borrow_mut","","",16,[[]]],[11,"try_from","","",16,[[],["result",4]]],[11,"try_into","","",16,[[],["result",4]]],[11,"type_id","","",16,[[],["typeid",3]]],[11,"vzip","","",16,[[]]],[11,"from","m_captcha::system","",17,[[]]],[11,"into","","",17,[[]]],[11,"to_owned","","",17,[[]]],[11,"clone_into","","",17,[[]]],[11,"borrow","","",17,[[]]],[11,"borrow_mut","","",17,[[]]],[11,"try_from","","",17,[[],["result",4]]],[11,"try_into","","",17,[[],["result",4]]],[11,"type_id","","",17,[[],["typeid",3]]],[11,"vzip","","",17,[[]]],[11,"from","","",18,[[]]],[11,"into","","",18,[[]]],[11,"to_owned","","",18,[[]]],[11,"clone_into","","",18,[[]]],[11,"borrow","","",18,[[]]],[11,"borrow_mut","","",18,[[]]],[11,"try_from","","",18,[[],["result",4]]],[11,"try_into","","",18,[[],["result",4]]],[11,"type_id","","",18,[[],["typeid",3]]],[11,"vzip","","",18,[[]]],[11,"default","m_captcha::pow","",22,[[],["configbuilder",3]]],[11,"clone","","",22,[[],["configbuilder",3]]],[11,"clone","m_captcha::defense","",19,[[],["level",3]]],[11,"clone","","",0,[[],["levelbuilder",3]]],[11,"clone","","",2,[[],["defense",3]]],[11,"clone","","",1,[[],["defensebuilder",3]]],[11,"clone","m_captcha::errors","",3,[[],["captchaerror",4]]],[11,"clone","m_captcha::master","",4,[[],["master",3]]],[11,"clone","","",7,[[],["addsitebuilder",3]]],[11,"clone","m_captcha::mcaptcha","",9,[[],["mcaptcha",3]]],[11,"clone","","",8,[[],["mcaptchabuilder",3]]],[11,"clone","m_captcha::cache::hashcache","",21,[[],["hashcache",3]]],[11,"clone","m_captcha::cache::messages","",12,[[],["cachebuilder",3]]],[11,"clone","m_captcha::pow","",15,[[],["powconfig",3]]],[11,"clone","","",16,[[],["work",3]]],[11,"clone","m_captcha::system","",17,[[],["system",3]]],[11,"clone","","",18,[[],["systembuilder",3]]],[11,"default","m_captcha::defense","",0,[[]]],[11,"default","","",1,[[]]],[11,"default","m_captcha::master","",7,[[],["addsitebuilder",3]]],[11,"default","m_captcha::mcaptcha","",8,[[],["mcaptchabuilder",3]]],[11,"default","m_captcha::cache::hashcache","",21,[[],["hashcache",3]]],[11,"default","m_captcha::cache::messages","",12,[[],["cachebuilder",3]]],[11,"default","m_captcha::system","",18,[[],["systembuilder",3]]],[11,"eq","m_captcha::defense","",19,[[["level",3]]]],[11,"ne","","",19,[[["level",3]]]],[11,"eq","","",0,[[["levelbuilder",3]]]],[11,"ne","","",0,[[["levelbuilder",3]]]],[11,"eq","","",2,[[["defense",3]]]],[11,"ne","","",2,[[["defense",3]]]],[11,"eq","","",1,[[["defensebuilder",3]]]],[11,"ne","","",1,[[["defensebuilder",3]]]],[11,"eq","m_captcha::errors","",3,[[["captchaerror",4]]]],[11,"fmt","m_captcha::defense","",19,[[["formatter",3]],["result",6]]],[11,"fmt","","",0,[[["formatter",3]],["result",6]]],[11,"fmt","","",2,[[["formatter",3]],["result",6]]],[11,"fmt","","",1,[[["formatter",3]],["result",6]]],[11,"fmt","m_captcha::errors","",3,[[["formatter",3]],["result",6]]],[11,"fmt","m_captcha::mcaptcha","",9,[[["formatter",3]],["result",6]]],[11,"fmt","m_captcha::pow","",15,[[["formatter",3]],["result",6]]],[11,"fmt","","",16,[[["formatter",3]],["result",6]]],[11,"fmt","m_captcha::errors","",3,[[["formatter",3]],["result",6]]],[11,"handle","m_captcha::master","",4,[[["getsite",3]]]],[11,"handle","","",4,[[["addsite",3]]]],[11,"handle","m_captcha::mcaptcha","",9,[[["visitor",3]]]],[11,"handle","m_captcha::cache::hashcache","",21,[[["cache",3]]]],[11,"handle","","",21,[[["deletestring",3]]]],[11,"handle","","",21,[[["retrive",3]]]],[11,"serialize","m_captcha::pow","",15,[[],["result",4]]],[11,"serialize","","",16,[[],["result",4]]],[11,"salt","","",22,[[["string",3]],["configbuilder",3]]],[11,"build","","Builds a new <code>Config</code>.",22,[[],[["result",4],["config",3],["string",3]]]]],"p":[[3,"LevelBuilder"],[3,"DefenseBuilder"],[3,"Defense"],[4,"CaptchaError"],[3,"Master"],[3,"GetSite"],[3,"AddSite"],[3,"AddSiteBuilder"],[3,"MCaptchaBuilder"],[3,"MCaptcha"],[3,"VisitorResult"],[3,"Cache"],[3,"CacheBuilder"],[3,"Retrive"],[3,"DeleteString"],[3,"PoWConfig"],[3,"Work"],[3,"System"],[3,"SystemBuilder"],[3,"Level"],[3,"Visitor"],[3,"HashCache"],[3,"ConfigBuilder"]]}\
}');
addSearchOptions(searchIndex);initSearch(searchIndex);