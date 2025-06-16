class FlexDictKey:
    def __init__(self, topic, domain):
        self.topic = topic
        self.domain = domain

    def __hash__(self):
        return hash((self.topic, self.domain))

    def __eq__(self, other):
        if isinstance(other, FlexDictKey):
            return (self.topic, self.domain) == (other.topic, other.domain)
        return False

    def matches(self, topic=None, domain=None):
        """For partial matching (for slicing-like behavior)."""
        return ((topic is None or self.topic == topic) and
                (domain is None or self.domain == domain))

    def __repr__(self):
        return f"Key({self.topic}, {self.domain})"

class FlexDict(dict):
    def __getitem__(self, key):
        # If key is tuple of length 2
        if isinstance(key, tuple) and len(key) == 2:
            topic, domain = key

            # Handle slicing when topic or domain is a slice
            if isinstance(topic, slice) or isinstance(domain, slice):
                topic_filter = (lambda k: True) if isinstance(topic, slice) else (lambda k: k.topic == topic)
                domain_filter = (lambda k: True) if isinstance(domain, slice) else (lambda k: k.domain == domain)

                result = {k: v for k, v in self.items() if topic_filter(k) and domain_filter(k)}

                # Flatten results if only one side is sliced
                if isinstance(topic, slice) and not isinstance(domain, slice):
                    return {k.topic: v for k, v in result.items()}
                elif not isinstance(topic, slice) and isinstance(domain, slice):
                    return {k.domain: v for k, v in result.items()}
                else:
                    return result

            # No slices: wrap key and do exact lookup
            wrapped_key = FlexDictKey(topic, domain)
            return super().__getitem__(wrapped_key)

        # If key is already a Key instance (no slicing support here)
        elif isinstance(key, FlexDictKey):
            return super().__getitem__(key)

        else:
            raise KeyError(f"Invalid key type: {type(key)}")
    
    def __setitem__(self, key, value):
        if isinstance(key, tuple) and len(key) == 2:
            topic, domain = key
            key = FlexDictKey(topic, domain)
        super().__setitem__(key, value)

    def key_present(self, topic=None, domain=None) -> bool:
        """
        Check if any key matches the given topic and/or domain,
        where topic and/or domain can be values or slice objects.
        Returns True if any matching key exists, False otherwise.

        Examples:
        key_or_slice_present(topic='network', domain=1)
        key_or_slice_present(topic='network', domain=slice(None))
        key_or_slice_present(topic=slice(None), domain=2)
        """

        if topic is None and domain is None:
            return False  # no criteria to match

        # If no slices, just check exact key
        if not isinstance(topic, slice) and not isinstance(domain, slice):
            return FlexDictKey(topic, domain) in self

        # Otherwise check if any key matches the slice pattern
        for k in self.keys():
            topic_match = (True if topic is None or isinstance(topic, slice) else k.topic == topic)
            domain_match = (True if domain is None or isinstance(domain, slice) else k.domain == domain)

            # For slices, treat them as wildcard (match anything)
            # You could expand this later to handle specific slice ranges if desired

            if topic_match and domain_match:
                return True

        return False

    def related_keys(self, *, topic=None, domain=None):
        """
        If 'domain' is provided, returns list of all topics containing that domain.
        If 'topic' is provided, returns list of all domains for that topic.
        Exactly one of 'topic' or 'domain' must be provided.
        """
        if (topic is None) == (domain is None):
            raise ValueError("Specify exactly one of 'topic' or 'domain'")

        if domain is not None:
            # Return topics that have this domain
            return list({key.topic for key in self.keys() if key.domain == domain})

        if topic is not None:
            # Return domains associated with this topic
            return list({key.domain for key in self.keys() if key.topic == topic})

    def most_nodes(self, top_n=6):
        """
        Return a list of the top `top_n` Keys sorted descending
        by the size of their corresponding set values.
        """
        # Sort items by length of set (value), descending
        sorted_items = sorted(
            self.items(),
            key=lambda item: len(item[1]),
            reverse=True
        )
        
        # Extract just the keys for top_n items
        return [key for key, value in sorted_items[:top_n]]
    
    def to_dict(self):
        output = {}
        for key, value in self.items():
            topic = key.topic
            domain = str(key.domain)  # convert domain to string for JSON safety
            output.setdefault(topic, {})[domain] = list(value)

        # Collect all unique domains
        all_domains = {domain for topic in output for domain in output[topic]}

        # Build reversed dict: domain -> topic -> list
        return {
            domain: {
                topic: sorted(output[topic][domain])
                for topic in sorted(output)
                if domain in output[topic]
            }
            for domain in sorted(all_domains)
        }
    
    @staticmethod
    def flatten_dict(input_dict):
        """
        Flattens a nested dictionary structure into a single-level dictionary.
        The keys are tuples of (topic, domain) and the values are lists.
        """
        return set().union(*input_dict.values())


if __name__ == "__main__":
    d = FlexDict()
    d['network', 1] = 'data1'
    d['network', 2] = 'data2'
    d['storage', 1] = 'data3'

    print(d['network', 1])    # 'data1'
    print(d['network', :])    # All entries with topic 'network'
    print(d[:, 1])            # All entries in domain 1
    # print(d[:, :])          # Everything

    print(d.related_keys(topic='network'))  # [1, 2]
    print(d.related_keys(domain=1))         # ['network', 'storage']