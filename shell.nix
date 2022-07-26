with import <nixpkgs> {};
mkShell {
  buildInputs = [ 
    secp256k1 
    haskell.compiler.ghc8107 
    cabal-install 
    ormolu
    hlint
  ];
}
