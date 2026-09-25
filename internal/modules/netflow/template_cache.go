package netflow

import (
	"container/list"
	"fmt"
	"sync"
)

// templateCache holds templates per (sourceID, domainID, templateID) with LRU eviction.
type templateCache struct {
	mu      sync.RWMutex
	maxSize int // max templates per exporter
	cache   map[string]*cachedTemplate
	lru     *list.List // ordered by access; oldest at front
	element map[string]*list.Element
}

type cachedTemplate struct {
	sourceID   uint32
	domainID   uint32
	templateID uint16
	fields     []field9  // for NetFlow v9
	fieldsIP   []fieldIP // for IPFIX
	isIPFIX    bool
}

func newTemplateCache(maxSize int) *templateCache {
	return &templateCache{
		maxSize: maxSize,
		cache:   make(map[string]*cachedTemplate),
		lru:     list.New(),
		element: make(map[string]*list.Element),
	}
}

func (c *templateCache) key(sourceID uint32, domainID uint32, templateID uint16) string {
	return fmt.Sprintf("%d/%d/%d", sourceID, domainID, templateID)
}

// Store adds or replaces a template, evicting the LRU if needed.
func (c *templateCache) Store9(sourceID uint32, domainID uint32, tmpl *template9, fields []field9) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := c.key(sourceID, domainID, tmpl.templateID)

	// If already present, remove from LRU
	if elem, ok := c.element[k]; ok {
		c.lru.Remove(elem)
		delete(c.element, k)
	}

	// If cache full, evict oldest
	if len(c.cache) >= c.maxSize {
		if elem := c.lru.Front(); elem != nil {
			oldK := elem.Value.(string)
			c.lru.Remove(elem)
			delete(c.element, oldK)
			delete(c.cache, oldK)
		}
	}

	// Store new template
	ct := &cachedTemplate{
		sourceID:   sourceID,
		domainID:   domainID,
		templateID: tmpl.templateID,
		fields:     fields,
		isIPFIX:    false,
	}
	c.cache[k] = ct
	elem := c.lru.PushBack(k)
	c.element[k] = elem
}

// StoreIP adds or replaces an IPFIX template.
func (c *templateCache) StoreIP(domainID uint32, templateID uint16, fields []fieldIP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := fmt.Sprintf("0/%d/%d", domainID, templateID)

	if elem, ok := c.element[k]; ok {
		c.lru.Remove(elem)
		delete(c.element, k)
	}

	if len(c.cache) >= c.maxSize {
		if elem := c.lru.Front(); elem != nil {
			oldK := elem.Value.(string)
			c.lru.Remove(elem)
			delete(c.element, oldK)
			delete(c.cache, oldK)
		}
	}

	ct := &cachedTemplate{
		domainID:   domainID,
		templateID: templateID,
		fieldsIP:   fields,
		isIPFIX:    true,
	}
	c.cache[k] = ct
	elem := c.lru.PushBack(k)
	c.element[k] = elem
}

// Get retrieves a template and marks it as recently used.
func (c *templateCache) Get9(sourceID uint32, domainID uint32, templateID uint16) ([]field9, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := c.key(sourceID, domainID, templateID)
	ct, ok := c.cache[k]
	if !ok || ct.isIPFIX {
		return nil, false
	}

	// Mark as recently used
	if elem, ok := c.element[k]; ok {
		c.lru.MoveToBack(elem)
	}

	return ct.fields, true
}

// GetIP retrieves an IPFIX template.
func (c *templateCache) GetIP(domainID uint32, templateID uint16) ([]fieldIP, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := fmt.Sprintf("0/%d/%d", domainID, templateID)
	ct, ok := c.cache[k]
	if !ok || !ct.isIPFIX {
		return nil, false
	}

	if elem, ok := c.element[k]; ok {
		c.lru.MoveToBack(elem)
	}

	return ct.fieldsIP, true
}

// Count returns the number of cached templates.
func (c *templateCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Clear removes all templates.
func (c *templateCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cachedTemplate)
	c.lru = list.New()
	c.element = make(map[string]*list.Element)
}
