# Standard Library Imports
from enum import Enum

# Local Application Imports
from src.log_handler import logging
from src.rtps_capture import PlotScale

logger = logging.getLogger(__name__)

class MenuOption(Enum):
    PRINT_STATS = '0'
    PLOT_COUNT = '1'
    PLOT_SIZE = '2'
    PLOT_GRAPH = '3'
    CHANGE_SCALE = '4'
    TOGGLE_DISCOVERY = '5'
    SAVE_EXCEL = '6'
    EXIT = '7'
    INVALID = 'invalid'  # For clarity

def get_user_menu_choice(scale, plot_discovery) -> tuple[MenuOption, PlotScale, bool, str]:
    print("\n--- Menu ---")
    print("0. Print Statistics")
    print("1. Plot Message Count")
    print("2. Plot Message Size")
    print("3. Plot Node Graph")
    print("4. Change Scale")
    print("5. Include Discovery Frames")
    print("6. Save to Excel")
    print("7. Exit")

    topic = None

    choice = input(f"Enter your choice (0-{MenuOption.EXIT.value}): ")
    logger.debug(f"User choice: {choice}")

    try:
        selected_option = MenuOption(choice)
    except ValueError:
        print(f"Invalid input. Please enter a number between 0 and {MenuOption.EXIT.value}.")
        return (MenuOption.INVALID, scale, plot_discovery, None)
    if selected_option == MenuOption.PLOT_GRAPH:
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

    return (selected_option, scale, plot_discovery, topic)