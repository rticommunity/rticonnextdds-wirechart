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

# Third-Party Library Imports
from enum import Enum, auto
import tkinter as tk
from tkinter import ttk, simpledialog
from typing import Union

# Local Imports
from src.flex_dictionary import FlexDict

class TopicDomainDropdownDialog(simpledialog.Dialog):
    ALL = "ALL"

    class InputType(Enum):
        TOPIC = auto()
        DOMAIN = auto()

    def __init__(self, parent, d: FlexDict, title: str="Topic and Domain", prompt: str="Select Topic and Domain Filters"):
        """
        Initializes the TopicDomainDropdownDialog with two combo boxes.

        Args:
            parent: The parent window.
            title (str): The title of the dialog.
            prompt (str): The prompt to display above the combo boxes.
            data (FlexDict): The data source for the combo boxes.
        """
        self.d = d
        self.prompt = prompt
        self.topic_selected = None
        self.domain_selected = None
        self._user_ok = False

        topics, domains = self.d.get_all_topics_and_domains()
        self.topics = [self.ALL] + sorted(topics)
        self.domains = [self.ALL] + sorted(domains)

        super().__init__(parent, title)

    def body(self, master):
        """
        Creates the body of the dialog with two combo boxes and a reset button.

        Args:
            master: The parent widget.

        Returns:
            ttk.Combobox: The first combo box to receive focus.
        """
        # Adjust the dialog width by spanning more columns
        ttk.Label(master, text=self.prompt).grid(row=0, column=0, columnspan=4, padx=10, pady=10)

        # Topic Combo Box
        ttk.Label(master, text="Topic:").grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="w")
        self.chosen_topic = tk.StringVar()
        self.topic_dropdown = ttk.Combobox(master, textvariable=self.chosen_topic, values=self.topics, state="readonly", width=60)  # Wide enough for topics
        self.topic_dropdown.grid(row=2, column=0, columnspan=2, padx=10, pady=5)
        self.topic_dropdown.current(0)  # Set default selection
        self.topic_dropdown.bind("<<ComboboxSelected>>", self.on_topic_selected)

        # Domain Combo Box
        ttk.Label(master, text="Domain:").grid(row=1, column=2, columnspan=2, padx=10, pady=5, sticky="w")
        self.chosen_domain = tk.StringVar()
        self.domain_dropdown = ttk.Combobox(master, textvariable=self.chosen_domain, values=self.domains, state="readonly", width=8)  # Reduced width for domains
        self.domain_dropdown.grid(row=2, column=2, columnspan=2, padx=10, pady=5)
        self.domain_dropdown.current(0)  # Set default selection
        self.domain_dropdown.bind("<<ComboboxSelected>>", self.on_domain_selected)

        # Reset Button
        self.reset_button = ttk.Button(master, text="Reset", command=self.on_reset_clicked)
        self.reset_button.grid(row=3, column=0, columnspan=4, pady=10)

        return self.topic_dropdown  # Set focus to the first combo box

    def apply(self):
        """
        Saves the selections from both combo boxes when the dialog is closed.
        """
        self.topic_selected = TopicDomainDropdownDialog._all_to_none(self.chosen_topic.get(),
                                                                     TopicDomainDropdownDialog.InputType.TOPIC)
        self.domain_selected = TopicDomainDropdownDialog._all_to_none(self.chosen_domain.get(),
                                                                      TopicDomainDropdownDialog.InputType.DOMAIN)
        self._user_ok = True

    def on_topic_selected(self, event):
        """
        Callback for when the first combo box selection changes.

        Args:
            event: The event object.
        """
        topic = TopicDomainDropdownDialog._all_to_none(self.chosen_topic.get(),
                                                       TopicDomainDropdownDialog.InputType.TOPIC)
        self.domain_dropdown['values'] = self.d.related_keys(topic=topic)

    def on_domain_selected(self, event):
        """
        Callback for when the second combo box selection changes.

        Args:
            event: The event object.
        """
        domain = TopicDomainDropdownDialog._all_to_none(self.chosen_domain.get(),
                                                        TopicDomainDropdownDialog.InputType.DOMAIN)
        self.topic_dropdown['values'] = self.d.related_keys(domain=domain)

    def on_reset_clicked(self):
        """
        Callback for when the reset button is clicked.

        This method resets both combo boxes to their default state.
        """
        # Reset the values in the combo boxes
        self.topic_dropdown['values'] = self.topics
        self.domain_dropdown['values'] = self.domains

        # Reset the display value to the first element in the list
        self.chosen_topic.set(self.topics[0])  # Set to the first element in topics
        self.chosen_domain.set(self.domains[0])  # Set to the first element in domains

    def user_ok(self) -> bool:
        """
        Checks if the user confirmed the dialog.

        Returns:
            bool: True if the dialog was confirmed, False otherwise.
        """
        return self._user_ok

    @staticmethod
    def _all_to_none(input: str, input_type: InputType) -> Union[str, int, None]:
        """
        Converts the input value from "ALL" to None, otherwise returns the input as is.
        Args:
            input: The input value to check.
        Returns:
            None if input is "ALL", otherwise returns the input value.
        """
        rval = None if input == TopicDomainDropdownDialog.ALL else input
        if input_type == TopicDomainDropdownDialog.InputType.DOMAIN and rval is not None:
            rval = int(rval)
        return rval

# Usage example
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    d = FlexDict()
    d['network', 1] = set(['data1'])
    d['network', 2] = set(['data2'])
    d['storage', 1] = set(['data3'])
    d['external', 4] = set(['data4'])

    dialog = TopicDomainDropdownDialog(root, d)

    if dialog.topic_selected and dialog.domain_selected:
        print("You selected:")
        print("Topic:", dialog.topic_selected)
        print("Domain:", dialog.domain_selected)