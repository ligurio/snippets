Feature: Google Searching
  As a web surfer, I want to search Google, so that I can learn new things.
  
  @automated @google @panda
  Scenario: Simple Google search
    Given a web browser is on the Google page
    When the search phrase "panda" is entered
    Then results for "panda" are shown
