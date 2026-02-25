package cache

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type Item[T any] struct {
	Value     T
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Cache[T any] struct {
	ttl        time.Duration
	maxEntries int
	items      map[string]Item[T]
	mu         sync.RWMutex
	sf         singleflight.Group
}

func New[T any](ttl time.Duration, maxEntries int) *Cache[T] {
	return &Cache[T]{
		ttl:        ttl,
		maxEntries: maxEntries,
		items:      make(map[string]Item[T], maxEntries),
	}
}

func (c *Cache[T]) GetFresh(key string) (T, bool) {
	var zero T
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(item.ExpiresAt) {
		return zero, false
	}
	return item.Value, true
}

func (c *Cache[T]) GetAny(key string) (Item[T], bool) {
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()
	return item, ok
}

func (c *Cache[T]) Set(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.maxEntries {
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}
	now := time.Now()
	c.items[key] = Item[T]{Value: value, CreatedAt: now, ExpiresAt: now.Add(c.ttl)}
}

func (c *Cache[T]) GetOrLoad(key string, loader func() (T, error)) (T, error) {
	if v, ok := c.GetFresh(key); ok {
		return v, nil
	}

	v, err, _ := c.sf.Do(key, func() (any, error) {
		if cached, ok := c.GetFresh(key); ok {
			return cached, nil
		}
		loaded, loadErr := loader()
		if loadErr != nil {
			return nil, loadErr
		}
		c.Set(key, loaded)
		return loaded, nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return v.(T), nil
}
