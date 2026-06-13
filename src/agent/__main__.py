import sys
from agent.entry_controllers.run_controller import RunController
from agent.entry_controllers.registration_controller import RegistrationController

def main():
    args = sys.argv[1:]
    if len(args) > 0 and args[0] == "--register":
        RegistrationController().run(args)
    else:
        RunController().run(args)

if __name__ == "__main__":
    main()
