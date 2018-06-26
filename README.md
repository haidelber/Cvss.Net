# Cvss.Net

![NuGet](https://img.shields.io/nuget/v/Cvss.Net.svg)
![NuGet](https://img.shields.io/nuget/dt/Cvss.Net.svg)

A utility library to handle Common Vulnerability Scoring System (CVSS) v3 Vectors and calculate their scores.

# Usage

The parsing and scoring logic is encapsulated in the CvssV3 class.

## Parsing CVSS V3 vectors

Simply do this by calling the constructor of CvssV3:
```C#
 var cvss = new CvssV3("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L");
```

## CvssBuilder

If you want to create a new metric use:
```C#
var cvss = CvssBuilder.NewV3().AttackComplexity(AttackComplexity.High).AttackVector(AttackVector.Physical)
  .PrivilegesRequired(PrivilegesRequired.None).UserInteraction(UserInteraction.None)
  .Scope(Scope.Unchanged).ConfidentialityImpact(Impact.High).IntegrityImpact(Impact.Low)
  .AvailabilityImpact(Impact.None).Build();
```
Calculation and validation is done when calling `Build()`.

If you want to create a metric from an existing metric use:
```C#
var newCvss = CvssBuilder.FromExistingV3(cvss).ModifiedAttackVector(AttackVector.Local);
```

# Contribution

If you feel like extending this lib feel free to submit a pull request.
