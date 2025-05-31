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

# Standard Library Imports
from enum import IntEnum, auto
from dataclasses import dataclass

# Local Application Imports
from src.log_handler import logging
from src.rtps_capture import PlotScale

logger = logging.getLogger(__name__)

class StandardMenuOption(IntEnum):
    INVALID = -1  # For clarity
    PRINT_CAPTURE_SUMMARY = auto()
    PRINT_TOPICS = auto()
    PRINT_STATS_COUNT = auto()
    PRINT_STATS_BYTES = auto()
    PLOT_BAR_CHART_COUNT = auto()
    PLOT_BAR_CHART_BYTES = auto()
    PLOT_TOPOLOGY_GRAPH = auto()
    CHANGE_SCALE = auto()
    TOGGLE_DISCOVERY = auto()
    SAVE_EXCEL = auto()
    EXIT = auto()

class MenuType(IntEnum):
    STANDARD = auto()


@dataclass
class MenuState:
    scale: PlotScale = PlotScale.LINEAR
    plot_discovery: bool = False
    menu_state: MenuType = MenuType.STANDARD


def get_user_menu_choice(state: MenuState) -> tuple[StandardMenuOption, MenuState]:
    print(f"\n{'-' * 25}")
    topic = None
    choice = None
    if state.menu_state == MenuType.STANDARD:
        print(f"{StandardMenuOption.PRINT_CAPTURE_SUMMARY.value}. Print Capture Summary")
        print(f"{StandardMenuOption.PRINT_TOPICS.value}. Print Topics")
        print(f"{StandardMenuOption.PRINT_STATS_COUNT.value}. Print Statistics (Count)")
        print(f"{StandardMenuOption.PRINT_STATS_BYTES.value}. Print Statistics (Bytes)")
        print(f"{StandardMenuOption.PLOT_BAR_CHART_COUNT.value}. Plot Bar Chart (Count)")
        print(f"{StandardMenuOption.PLOT_BAR_CHART_BYTES.value}. Plot Bar Chart (Bytes)")
        print(f"{StandardMenuOption.PLOT_TOPOLOGY_GRAPH.value}. Plot Topology Graph")
        print(f"{StandardMenuOption.CHANGE_SCALE.value}. Toggle Scale (Current: {state.scale.name.capitalize()})")
        print(f"{StandardMenuOption.TOGGLE_DISCOVERY.value}. Toggle Include Discovery Frames (Current: {'Yes' if state.plot_discovery else 'No'})")
        print(f"{StandardMenuOption.SAVE_EXCEL.value}. Save to Excel")
        print(f"{StandardMenuOption.EXIT.value}. Exit")

        choice = input(f"Enter your choice (0-{StandardMenuOption.EXIT.value}): ")
        logger.debug(f"User choice: {choice}")

        try:
            selected_option = StandardMenuOption(int(choice))
        except ValueError:
            print(f"Invalid input. Please enter a number between 0 and {StandardMenuOption.EXIT.value}.")
            return (StandardMenuOption.INVALID, topic, state)
        if selected_option == StandardMenuOption.PLOT_TOPOLOGY_GRAPH:
            topic = input("Enter topic to plot (leave blank to include the 6 largest topics): ").strip()
            if topic:
                logger.debug(f"User entered topic: {topic}")
            else:
                logger.debug("User chose to plot all topics.")
        elif selected_option == StandardMenuOption.CHANGE_SCALE:
            state.scale = PlotScale.LOGARITHMIC if state.scale == PlotScale.LINEAR else PlotScale.LINEAR
        elif selected_option == StandardMenuOption.TOGGLE_DISCOVERY:
            state.plot_discovery = not state.plot_discovery

    print(f"{'-' * 25}")
    return (selected_option, topic, state)