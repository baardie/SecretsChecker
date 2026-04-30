using System.Reflection;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Tests.Invariants;

/// <summary>
/// Reflection-based guards that protect the core safety invariant (R1). These tests must keep
/// passing for every PR; if anyone adds a value-bearing field to a public type, or makes
/// <see cref="RawMatch"/> public, the build fails.
/// </summary>
public sealed class SafetyInvariantTests
{
    private static readonly Assembly CoreAssembly = typeof(Finding).Assembly;

    private static readonly string[] ForbiddenPropertyNames =
    {
        "value", "secret", "raw", "content", "rawvalue", "secretvalue",
    };

    [Fact]
    public void Public_types_must_not_expose_secret_value_properties()
    {
        var offenders = new List<string>();

        foreach (var type in CoreAssembly.GetExportedTypes())
        {
            foreach (var prop in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                if (prop.PropertyType != typeof(string))
                {
                    continue;
                }

                if (ForbiddenPropertyNames.Contains(prop.Name, StringComparer.OrdinalIgnoreCase))
                {
                    offenders.Add($"{type.FullName}.{prop.Name}");
                }
            }

            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                if (field.FieldType != typeof(string))
                {
                    continue;
                }

                if (ForbiddenPropertyNames.Contains(field.Name, StringComparer.OrdinalIgnoreCase))
                {
                    offenders.Add($"{type.FullName}.{field.Name}");
                }
            }
        }

        offenders.Should().BeEmpty(
            "no public type in SecretsScanner.Core may expose a string field/property named like a secret value (R1)");
    }

    [Fact]
    public void RawMatch_must_be_internal_and_sealed()
    {
        var rawMatch = CoreAssembly.GetTypes().Single(t => t.Name == "RawMatch");

        rawMatch.IsPublic.Should().BeFalse("RawMatch must not be public — it carries the raw secret value (R1)");
        rawMatch.IsSealed.Should().BeTrue("RawMatch must be sealed");
    }

    [Fact]
    public void Sanitiser_must_be_internal()
    {
        var sanitiser = CoreAssembly.GetTypes().Single(t => t.Name == "Sanitiser");

        sanitiser.IsPublic.Should().BeFalse("Sanitiser handles raw values; only the core library may invoke it");
    }

    [Fact]
    public void Finding_must_not_have_raw_value_property()
    {
        typeof(Finding).GetProperties()
            .Select(p => p.Name)
            .Should().NotContain("Value", "Finding must never carry the raw value");
    }

    [Fact]
    public void No_public_method_may_take_or_return_RawMatch()
    {
        var rawMatch = CoreAssembly.GetTypes().Single(t => t.Name == "RawMatch");
        var offenders = new List<string>();

        foreach (var type in CoreAssembly.GetExportedTypes())
        {
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                if (Mentions(method.ReturnType, rawMatch) ||
                    method.GetParameters().Any(p => Mentions(p.ParameterType, rawMatch)))
                {
                    offenders.Add($"{type.FullName}.{method.Name}");
                }
            }
        }

        offenders.Should().BeEmpty(
            "no public method may have RawMatch in its signature — direct, generic argument, or array (R1)");
    }

    private static bool Mentions(Type candidate, Type forbidden)
    {
        if (candidate == forbidden)
        {
            return true;
        }

        if (candidate.HasElementType && Mentions(candidate.GetElementType()!, forbidden))
        {
            return true;
        }

        if (candidate.IsGenericType)
        {
            foreach (var arg in candidate.GetGenericArguments())
            {
                if (Mentions(arg, forbidden))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
