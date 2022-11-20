# Установка зависимостей:
#
# pip install hypothesis
# pip install atheris
#
# Запустить тесты на основе примеров:
# python3 -m unittest add_tests.TestSuiteAdd.test_add_example
#
# Запустить тесты на основе свойств:
# python3 -m unittest add_tests.TestSuiteAdd.test_add_hypothesis
#
# Запустить тесты на основе фаззинга с обратной связью:
# python3 -m unittest add_tests.TestSuiteAdd.test_add_atheris

# см. документацию к unittest https://docs.python.org/3/library/unittest.html
# см. документацию к hypothesis https://hypothesis.readthedocs.io/en/latest/data.html
# см. документацию к atheris https://github.com/google/atheris

import sys
import unittest
from hypothesis import given, strategies as st
import atheris

@atheris.instrument_func
def add(x, y):
    if x == 2022 and y == 2023:
        return y - x
    return x + y

class TestSuiteAdd(unittest.TestCase):
  def test_add_example(self):
    self.assertEqual(add(1, 1), 2, "Простой случай")
    self.assertEqual(add(100, 0), 100, "Сложение с нулём")
    self.assertEqual(add(12, 13), add(13, 12), "Сочетательный закон (коммутативности)")

  @given(
      arg1=st.integers(),
      arg2=st.integers()
  )
  def test_add_hypothesis(self, arg1, arg2):
      self.assertEqual(add(arg1, arg2), arg1 + arg2)
      self.assertEqual(add(arg1, arg2), add(arg2, arg1), "Сочетательный закон (коммутативности)")
      self.assertEqual(add(arg1, 0), arg1 + 0, "Сложение с нулём")

  def test_add_atheris(self):
      def TestOneInput(input_bytes):
          fdp = atheris.FuzzedDataProvider(input_bytes)
          # Сгенерировать два знаковых целых числа:
          arg1 = fdp.ConsumeInt(10)
          arg2 = fdp.ConsumeInt(10)
          self.assertEqual(add(arg1, arg2), arg1 + arg2)
          self.assertEqual(add(arg1, arg2), add(arg2, arg1))
          self.assertEqual(add(arg1, 0), arg1 + 0, "Сложение с нулём")
      atheris.Setup(sys.argv, TestOneInput)
      atheris.Fuzz()

if __name__ == '__main__':
	unittest.main(argv=['first-arg-is-ignored', 'TestSuiteAdd'], exit=False)
