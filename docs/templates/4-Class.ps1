class ClassName {

    #region: Properties
    [ValidateNotNullOrEmpty()][string] $Prop1
    [string] $Prop2
    [string] $Prop3
    [int[]] $Integers = 0..10
    [int] hidden $Slots = 8
    #endregion



    #region: Constructor
    ClassName(
        [string] $prop1,
        [string] $prop2,
        [string] $prop3
    ){
        $this.Prop1 = $prop1
        $this.Prop2 = $prop2
        $this.Prop3 = $prop3
    }
    #endregion



    #region: Method
    # Method [GetEvenIntegers]: No return value
    [void] GetEvenIntegers(){
        # note: this doesn't go to the pipeline
        $this.Integers.Where({ ($_ % 2) -eq 0})
    }

    # Method [SayHello]: Returns System.String
    [string] SayHello(){
        # this doesn't go to the pipeline
        "Good Morning"
        # this does go to the pipeline
        return "Hello World"
    }
    
    # Method [MakeOne]: Returns a new instance of this class
    [ClassName] MakeOne() {
        $return = [ClassName]::new("one","2","threefiddy")
        return $return
    }
    #endregion
}

# NOTES -------------------------------------------------------------------------------
# Generally I have not found classes to be practical for most use cases as of PowerShell 5.1
# I've left this template for future reference.  Unfortunately, classes are not visible or 
# usable within other cmdlets in the module unless the entire class definition is placed
# directly in the FILE(s) that require them.  At this point it is easier to create
# classes in C# library than to use PowerShell classes.

# HOW TO -------------------------------------------------------------------------------
# Instantiating custom classes - just like .net types.
# Example 1: Instantiate "ClassName"
# PS> $thing = [ClassName]::new("hello world", "goodbye")
# Example 2: Instantiate "ClassName"
# PS> $thing = New-Object -TypeName ClassName -ArgumentList @("hello world", "goodbye")