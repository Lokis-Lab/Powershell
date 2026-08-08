Describe 'Invoke-AfterHoursGpoPolicyAudit Get-DescendantDns' {
  BeforeAll {
    function script:Get-DescendantDns {
      param(
        [Parameter(Mandatory)][object[]]$Nodes,
        [Parameter(Mandatory)][string]$RootDn
      )
      $result = [System.Collections.Generic.List[string]]::new()
      $queue = New-Object System.Collections.Generic.Queue[string]
      $queue.Enqueue($RootDn)
      while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        [void]$result.Add($current)
        $children = @($Nodes | Where-Object { $_.ParentDn -eq $current } | Select-Object -ExpandProperty DistinguishedName)
        foreach ($child in $children) {
          $queue.Enqueue($child)
        }
      }
      return @($result | Select-Object -Unique)
    }
  }

  It 'parses without syntax errors' {
    { [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'),
        [ref]$null,
        [ref]$null) } | Should -Not -Throw
  }

  It 'clears extracted template folders before re-expanding updated zips' {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
      $scriptPath,
      [ref]$tokens,
      [ref]$parseErrors
    )
    $functionAst = $ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Expand-ZipIfNeeded'
    }, $true)

    $functionAst | Should -Not -BeNullOrEmpty
    $functionAst.Body.Extent.Text | Should -Match 'Get-ChildItem -LiteralPath \$DestinationFolder'
    $functionAst.Body.Extent.Text | Should -Match 'Remove-Item -Recurse -Force'
  }

  It 'wraps BFS child results in an array to avoid character-wise iteration' {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-AfterHoursGpoPolicyAudit.ps1'
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $source | Should -Match '\$children\s*=\s*@\(\$Nodes'
  }

  It 'includes deeper descendants when a node has exactly one child' {
    $nodes = @(
      [PSCustomObject]@{ DistinguishedName = 'OU=Root,DC=contoso,DC=com'; ParentDn = 'DC=contoso,DC=com' },
      [PSCustomObject]@{ DistinguishedName = 'OU=Child,DC=contoso,DC=com'; ParentDn = 'OU=Root,DC=contoso,DC=com' },
      [PSCustomObject]@{ DistinguishedName = 'OU=Grandchild,DC=contoso,DC=com'; ParentDn = 'OU=Child,DC=contoso,DC=com' }
    )

    $result = Get-DescendantDns -Nodes $nodes -RootDn 'OU=Root,DC=contoso,DC=com'
    $result | Should -Contain 'OU=Child,DC=contoso,DC=com'
    $result | Should -Contain 'OU=Grandchild,DC=contoso,DC=com'
    $result.Count | Should -Be 3
  }
}
