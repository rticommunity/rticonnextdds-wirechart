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

# Local Application Imports
from src.log_handler import logging
from src.rtps_capture import PlotScale

logger = logging.getLogger(__name__)

class MenuOption(IntEnum):
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

def get_user_menu_choice(scale, plot_discovery) -> tuple[MenuOption, PlotScale, bool, str]:
    print(f"\n{'-' * 25}")
    print(f"{MenuOption.PRINT_CAPTURE_SUMMARY.value}. Print Capture Summary")
    print(f"{MenuOption.PRINT_TOPICS.value}. Print Topics")
    print(f"{MenuOption.PRINT_STATS_COUNT.value}. Print Statistics (Count)")
    print(f"{MenuOption.PRINT_STATS_BYTES.value}. Print Statistics (Bytes)")
    print(f"{MenuOption.PLOT_BAR_CHART_COUNT.value}. Plot Bar Chart (Count)")
    print(f"{MenuOption.PLOT_BAR_CHART_BYTES.value}. Plot Bar Chart (Bytes)")
    print(f"{MenuOption.PLOT_TOPOLOGY_GRAPH.value}. Plot Topology Graph")
    print(f"{MenuOption.CHANGE_SCALE.value}. Change Scale")
    print(f"{MenuOption.TOGGLE_DISCOVERY.value}. Include Discovery Frames")
    print(f"{MenuOption.SAVE_EXCEL.value}. Save to Excel")
    print(f"{MenuOption.EXIT.value}. Exit")

    topic = None

    choice = input(f"Enter your choice (0-{MenuOption.EXIT.value}): ")
    logger.debug(f"User choice: {choice}")

    try:
        selected_option = MenuOption(int(choice))
    except ValueError:
        print(f"Invalid input. Please enter a number between 0 and {MenuOption.EXIT.value}.")
        return (MenuOption.INVALID, scale, plot_discovery, None)
    if selected_option == MenuOption.PLOT_TOPOLOGY_GRAPH:
        topic = input("Enter topic to plot (leave blank to include the 6 largest topics): ").strip()
        if topic:
            logger.debug(f"User entered topic: {topic}")
        else:
            logger.debug("User chose to plot all topics.")
    elif selected_option == MenuOption.CHANGE_SCALE:
        print("\n-- Change Scale --")
        print("a. Linear")
        print("b. Logarithmic")
        sub_choice = input("Choose scale (a/b): ")
        logger.debug(f"User scale choice: {sub_choice}")
        match sub_choice.lower():
            case 'a':
                scale = PlotScale.LINEAR
                print("Scale set to Linear.")
            case 'b':
                scale = PlotScale.LOGARITHMIC
                print("Scale set to Logarithmic.")
            case _:
                print("Invalid scale choice.")
    elif selected_option == MenuOption.TOGGLE_DISCOVERY:
        print("\n-- Include Discovery Data --")
        print("a. No")
        print("b. Yes")
        sub_choice = input("Choose option (a/b): ")
        logger.debug(f"User discovery choice: {sub_choice}")
        match sub_choice.lower():
            case 'a':
                plot_discovery = False
                print("Discovery frames excluded from the plot.")
            case 'b':
                plot_discovery = True
                print("Discovery frames included in the plot.")
            case _:
                print("Invalid choice.")

    print(f"{'-' * 25}\n")
    return (selected_option, scale, plot_discovery, topic)