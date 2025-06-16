class FlexDictKey:
    def __init__(self, topic, domain) -> None:
        if topic is None or domain is None:
            raise ValueError("Both topic and domain must be specified (None is not allowed).")
        self.topic = topic
        self.domain = domain

    def __hash__(self) -> int:
        return hash((self.topic, self.domain))

    def __eq__(self, other) -> bool:
        if isinstance(other, FlexDictKey):
            return (self.topic, self.domain) == (other.topic, other.domain)
        return False

    def matches(self, topic=None, domain=None) -> bool:
        """Check if key matches given topic/domain; None means 'any'."""
        return ((topic is None or self.topic == topic) and
                (domain is None or self.domain == domain))

    def __repr__(self) -> str:
        return f"Key({self.topic}, {self.domain})"

class FlexDict(dict):
    def __getitem__(self, key) -> dict:
        if isinstance(key, tuple) and len(key) == 2:
            topic, domain = key

            # Handle wildcard (None) access
            result = {k: v for k, v in self.items() if k.matches(topic, domain)}

            if topic is None and domain is None:
                return result  # Full dict
            elif topic is None:
                return {k.topic: v for k, v in result.items()}
            elif domain is None:
                return {k.domain: v for k, v in result.items()}
            else:
                # Exact match: should return set, not dict
                return super().__getitem__(FlexDictKey(topic, domain))

        elif isinstance(key, FlexDictKey):
            return super().__getitem__(key)

        else:
            raise KeyError(f"Invalid key type: {type(key)}")

    def __setitem__(self, key, value) -> None:
        if isinstance(key, tuple) and len(key) == 2:
            topic, domain = key
            key = FlexDictKey(topic, domain)
        super().__setitem__(key, value)

    def key_present(self, topic=None, domain=None) -> bool:
        """Returns True if any key matches the given topic/domain pattern."""
        return any(k.matches(topic, domain) for k in self.keys())

    def related_keys(self, *, topic=None, domain=None) -> list:
        """Return domains for a topic, or topics for a domain (one of topic/domain must be given)."""
        if (topic is None) == (domain is None):
            raise ValueError("Specify exactly one of 'topic' or 'domain'")

        if domain is not None:
            return list({k.topic for k in self.keys() if k.domain == domain})
        else:
            return list({k.domain for k in self.keys() if k.topic == topic})

    def most_nodes(self, top_n=6, topic=None, domain=None):
        """
        Return the top `top_n` keys with the largest sets,
        optionally filtered by `topic` or `domain`.
        """
        # Filter items based on provided topic and/or domain
        filtered_items = [
            (key, value) for key, value in self.items()
            if (topic is None or key.topic == topic) and
            (domain is None or key.domain == domain)
        ]

        # Sort by length of set (value), descending
        sorted_items = sorted(filtered_items, key=lambda item: len(item[1]), reverse=True)

        # Return only the keys of the top_n items
        return [key for key, _ in sorted_items[:top_n]]

    def get_elements_as_set(self, topic=None, domain=None) -> set:
        """Return a flattened set of all values matching the topic/domain pattern."""
        result = self[topic, domain]
        if isinstance(result, dict):
            return self.flatten_dict(result)
        else:
            return result

    def to_dict(self) -> dict:
        """Convert FlexDict to nested dict for JSON serialization."""
        output = {}
        for key, value in self.items():
            topic = key.topic
            domain = str(key.domain)  # JSON-friendly
            output.setdefault(topic, {})[domain] = list(value)

        all_domains = {domain for topic in output for domain in output[topic]}
        return {
            domain: {
                topic: sorted(output[topic][domain])
                for topic in sorted(output)
                if domain in output[topic]
            }
            for domain in sorted(all_domains)
        }

    @staticmethod
    def flatten_dict(input_dict) -> set:
        """Flatten nested dict values into a single set."""
        return set().union(*input_dict.values())


if __name__ == "__main__":
    d = FlexDict()
    d['network', 1] = set(['data1'])
    d['network', 2] = set(['data2'])
    d['storage', 1] = set(['data3'])
    d['external', 4] = set(['data4'])

    print(d['network', 1])    # {'data1'}
    print(d[None, 1])         # {'network': {'data1'}, 'storage': {'data3'}}
    print(d['network', None]) # {1: {'data1'}, 2: {'data2'}}
    print(d[None, None])      # All entries (full dict)

    print("\nRelated Keys:")
    print(d.related_keys(topic='network'))  # [1, 2]
    print(d.related_keys(domain=1))         # ['network', 'storage']

    print("\nGet Elements as Set:")
    print(d.get_elements_as_set(topic='network'))   # {'data1', 'data2'}
    print(d.get_elements_as_set(domain=1))          # {'data1', 'data3'}
    print(d.get_elements_as_set())                  # {'data1', 'data2', 'data3'}
    print(d.get_elements_as_set(topic='network', domain=1))  # {'data1'}

    print("\nToDict:")
    print(d.to_dict())