package main

import (
	"testing"
)

func TestNormalizeURLWithIDs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL with user ID and role",
			input:    "http://example.com/user/1203094/role",
			expected: "http://example.com/user/_ID_/role",
		},
		{
			name:     "URL with nested path and ID",
			input:    "http://example.com/api/v1/users/456/profile",
			expected: "http://example.com/api/v1/users/_ID_/profile",
		},
		{
			name:     "URL with single ID at end",
			input:    "http://example.com/posts/789",
			expected: "http://example.com/posts/_ID_",
		},
		{
			name:     "URL with multiple IDs",
			input:    "http://example.com/user/123/post/456/comments",
			expected: "http://example.com/user/_ID_/post/_ID_/comments",
		},
		{
			name:     "URL with products and reviews IDs",
			input:    "http://example.com/products/9999/reviews/123",
			expected: "http://example.com/products/_ID_/reviews/_ID_",
		},
		{
			name:     "URL without numeric IDs",
			input:    "http://example.com/api/users",
			expected: "http://example.com/api/users",
		},
		{
			name:     "URL with version but no IDs",
			input:    "http://example.com/api/v2/data",
			expected: "http://example.com/api/v2/data",
		},
		{
			name:     "URL with order ID",
			input:    "http://example.com/orders/12345",
			expected: "http://example.com/orders/_ID_",
		},
		{
			name:     "URL with multiple nested IDs",
			input:    "http://api.example.com/v1/customers/99999/orders/88888/items/77777",
			expected: "http://api.example.com/v1/customers/_ID_/orders/_ID_/items/_ID_",
		},
		{
			name:     "URL with query parameters and ID",
			input:    "http://example.com/users/123?filter=active&sort=name",
			expected: "http://example.com/users/_ID_",
		},
		{
			name:     "URL with fragment and ID",
			input:    "http://example.com/docs/456#section",
			expected: "http://example.com/docs/_ID_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeURLWithIDs(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeURLWithIDs(%s) = %s; want %s", tt.input, result, tt.expected)
			}
		})
	}
}