import os
from fnmatch import filter

from kitty.model import Group, BaseField, Container


class Corpus(Container):
    def __init__(self, key, value, flags=0, fuzzable=False):
        super(Corpus, self).__init__(name=key, fields=[], fuzzable=fuzzable)    # Get access the logger object
        if not os.path.isdir(value):
            self.logger.error("{} is not a directory".format(value))
            raise Exception("{} is not a directory".format(value))

        self.logger.debug("Listing files from: {}".format(value))

        items = []
        corpus_path = os.path.abspath(value)
        for root, dirnames, filenames in os.walk(corpus_path):
            for filename in filter(filenames, "id*"):
                items.append(os.path.join(root, filename))

        self.logger.debug("Adding {} files to the corpus.".format(len(items)))

        fields = [
            Group(values=items, fuzzable=fuzzable, name="corpus")
        ]
        super(Corpus, self).__init__(name=key, fields=fields, fuzzable=fuzzable)
