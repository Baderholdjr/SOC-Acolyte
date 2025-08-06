from sqlalchemy.orm import Session
from . import response_actions as models
import uuid
from datetime import datetime, timezone


class ResponseActionService:
    """
    This service contains the business logic for handling and executing response actions.
    """

    def __init__(self, db: Session):
        self.db = db

    async def execute_action(self, action_id: uuid.UUID):
        """
        Executes a specific response action.

        This function currently simulates the action. In a real-world scenario, this
        is where the integration with external security tools (like firewalls,
        EDR solutions, etc.) would happen based on the action_type.
        """
        # Retrieve the action from the database
        action = self.db.query(models.ResponseAction).filter(models.ResponseAction.id == action_id).first()
        if not action:
            print(f"ERROR: Response action {action_id} not found during execution.")
            return

        print(f"SIMULATING execution of action '{action.action_type}' for alert '{action.alert_id}'...")

        simulated_success = True
        simulated_result = {"message": f"Successfully simulated execution of {action.action_type}."}

        # Update the status of the main action record
        action.status = "COMPLETED" if simulated_success else "FAILED"
        action.executed_at = datetime.now(timezone.utc)

        # Create a detailed execution log record
        new_execution = models.ResponseActionExecution(
            action_id=action.id,
            status="SUCCESS" if simulated_success else "FAILURE",
            result=simulated_result
        )
        self.db.add(new_execution)
        self.db.commit()

        print(f"SUCCESS: Logged execution for action {action_id}")
