use lru::LruCache;

pub(crate) struct DomainMap {
    domain: LruCache<String, (String, String)>,
}
