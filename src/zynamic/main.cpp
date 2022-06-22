/* SPDX-License-Identifier: GPL-3.0-only */

#include <zynamic/view/main_window.hpp>

#include <QApplication>

auto main(int argc, char *argv[]) -> int
{
  QApplication a(argc, argv);
  Zynamic::MainWindow w;
  w.show();
  return QApplication::exec();
}
