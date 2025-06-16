##############################################################################################
# (c) 2025-2025 Copyright, Real-Time Innovations, Inc. (RTI) All rights reserved.
#
# RTI grants Licensee a license to use, modify, compile, and create derivative works of the
# software solely for use with RTI Connext DDS. Licensee may redistribute copies of the
# software, provided that all such copies are subject to this license. The software is
# provided "as is", with no warranty of any type, including any warranty for fitness for any
# purpose. RTI is under no obligation to maintain or support the software. RTI shall not be
# liable for any incidental or consequential damages arising out of the use or inability to
# use the software.
#
##############################################################################################

class FlexDictKey:
    """
    Represents a composite key for the FlexDict class, consisting of a topic and a domain.

    Attributes:
        topic: The topic part of the key.
        domain: The domain part of the key.
    """

    def __init__(self, topic, domain) -> None:
        """
        Initializes a FlexDictKey instance.

        Args:
            topic: The topic part of the key.
            domain: The domain part of the key.

        Raises:
            ValueError: If either topic or domain is None.
        """
        if topic is None or domain is None:
            raise ValueError("Both topic and domain must be specified (None is not allowed).")
        self.topic = topic
        self.domain = domain

    def __hash__(self) -> int:
        """
        Returns a hash value for the key, allowing it to be used in dictionaries.

        Returns:
            int: The hash value of the key.
        """
        return hash((self.topic, self.domain))

    def __eq__(self, other) -> bool:
        """
        Checks equality between two FlexDictKey instances.

        Args:
            other: Another FlexDictKey instance.

        Returns:
            bool: True if the keys are equal, False otherwise.
        """
        if isinstance(other, FlexDictKey):
            return (self.topic, self.domain) == (other.topic, other.domain)
        return False

    def matches(self, topic=None, domain=None) -> bool:
        """
        Checks if the key matches the given topic and/or domain.

        Args:
            topic: The topic to match (or None to ignore).
            domain: The domain to match (or None to ignore).

        Returns:
            bool: True if the key matches, False otherwise.
        """
        return ((topic is None or self.topic == topic) and
                (domain is None or self.domain == domain))

    def __repr__(self) -> str:
        """
        Returns a string representation of the key.

        Returns:
            str: The string representation of the key.
        """
        return f"Key({self.topic}, {self.domain})"


class FlexDict(dict):
    """
    A specialized dictionary that uses composite keys (FlexDictKey) and supports slicing-like behavior.

    Methods:
        __getitem__: Retrieves values based on composite keys or slices.
        __setitem__: Sets values using composite keys.
        key_present: Checks if a key or slice exists in the dictionary.
        related_keys: Retrieves related keys based on topic or domain.
        most_nodes: Returns the top N keys with the largest set values.
        get_elements_as_set: Retrieves all elements for a specific topic and/or domain.
        to_dict: Converts the dictionary into a JSON-serializable format.
        flatten_dict: Flattens a nested dictionary into a single-level dictionary.
    """

    def __getitem__(self, key) -> dict:
        """
        Retrieves values based on composite keys or slices.

        Args:
            key: A tuple (topic, domain), a FlexDictKey, or None for wildcard access.

        Returns:
            dict or set: The value(s) associated with the key or slice.

        Raises:
            KeyError: If the key is invalid or not found.
        """
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
        """
        Sets values using composite keys.

        Args:
            key: A tuple (topic, domain) or a FlexDictKey.
            value: The value to associate with the key.
        """
        if isinstance(key, tuple) and len(key) == 2:
            topic, domain = key
            key = FlexDictKey(topic, domain)
        super().__setitem__(key, value)

    def key_present(self, topic=None, domain=None) -> bool:
        """
        Checks if any key matches the given topic and/or domain.

        Args:
            topic: The topic to match (or None to ignore).
            domain: The domain to match (or None to ignore).

        Returns:
            bool: True if any matching key exists, False otherwise.
        """
        return any(k.matches(topic, domain) for k in self.keys())

    def related_keys(self, *, topic=None, domain=None) -> list:
        """
        Retrieves related keys based on topic or domain.  Exactly one of topic or domain must be specified.

        Args:
            topic: The topic to match (or None to ignore).
            domain: The domain to match (or None to ignore).

        Returns:
            list: A list of related keys.

        Raises:
            ValueError: If neither or both topic and domain are provided.
        """
        if (topic is None) == (domain is None):
            raise ValueError("Specify exactly one of 'topic' or 'domain'")

        if domain is not None:
            return list({k.topic for k in self.keys() if k.domain == domain})
        else:
            return list({k.domain for k in self.keys() if k.topic == topic})

    def most_nodes(self, top_n=6, topic=None, domain=None):
        """
        Returns the top N keys with the most set elements, optionally filtered by topic or domain.

        Args:
            top_n: The number of keys to return.
            topic: The topic to filter by (or None to ignore).
            domain: The domain to filter by (or None to ignore).

        Returns:
            list: A list of the top N keys.
        """
        filtered_items = [
            (key, value) for key, value in self.items()
            if (topic is None or key.topic == topic) and
            (domain is None or key.domain == domain)
        ]
        sorted_items = sorted(filtered_items, key=lambda item: len(item[1]), reverse=True)
        return [key for key, _ in sorted_items[:top_n]]

    def get_elements_as_set(self, topic=None, domain=None) -> set:
        """
        Retrieves a flattened set of all values matching the topic/domain pattern.

        Args:
            topic: The topic to match (or None to ignore).
            domain: The domain to match (or None to ignore).

        Returns:
            set: A set of all matching elements.
        """
        result = self[topic, domain]
        if isinstance(result, dict):
            return self.flatten_dict(result)
        else:
            return result

    def to_dict(self) -> dict:
        """
        Converts the FlexDict to a nested dictionary for JSON serialization.

        Returns:
            dict: A JSON-serializable representation of the dictionary.
        """
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
        """
        Flattens a nested dictionary structure into a single-level set.

        Args:
            input_dict: The nested dictionary to flatten.

        Returns:
            set: A flattened set of all unique values.
        """
        return set().union(*input_dict.values())


if __name__ == "__main__":
    """
    Example usage of the FlexDict class.
    """
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